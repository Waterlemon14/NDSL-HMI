package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

// RevokedEntry records a single revoked certificate.
type RevokedEntry struct {
	SerialNumber string    `json:"serial_number"`
	RevokedAt    time.Time `json:"revoked_at"`
	Reason       string    `json:"reason,omitempty"`
}

// RevokeRequest is the JSON body for the /revoke endpoint.
type RevokeRequest struct {
	SerialNumber string `json:"serial_number"` // hex-encoded serial
	Certificate  string `json:"certificate"`   // PEM-encoded cert (alternative)
	Reason       string `json:"reason"`
}

// db is the connection pool to the Supabase Postgres database.
var db *pgxpool.Pool

// initDB connects to Postgres and ensures the revoked_certificates table exists.
func initDB(databaseURL string) error {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return fmt.Errorf("failed to parse database URL: %w", err)
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return fmt.Errorf("failed to create connection pool: %w", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}
	_, err = pool.Exec(context.Background(), `
	CREATE TABLE IF NOT EXISTS revoked_certificates (
		serial_number TEXT PRIMARY KEY,
		revoked_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		reason        TEXT
	)`)
	if err != nil {
		return fmt.Errorf("failed to create revoked_certificates table: %w", err)
	}
	log.Println("connected to database and ensured revoked_certificates table exists")
	db = pool
	return nil
}

type SubjectInfo struct {
	Country      string
	State        string
	Locality     string
	Organization string
	CommonName   string
}

type CSRData struct {
	PublicKey string
	IPAddress string
	Subject   SubjectInfo
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Printf("warning: could not load .env file: %v", err)
	}

	caCertPath := flag.String("ca-cert", "root-ca.crt", "Path to CA certificate (PEM)")
	caKeyPath := flag.String("ca-key", "root-ca.key", "Path to CA private key (PEM, PKCS#1, PKCS#8 or EC)")
	addr := flag.String("addr", ":15000", "HTTP listen address")
	validDays := flag.Int("days", 7, "Validity of issued certs in days")
	flag.Parse()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}
	var err error
	err = initDB(databaseURL)
	if err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}
	defer db.Close()

	caCert, caKey, err := loadCA(*caCertPath, *caKeyPath)
	if err != nil {
		log.Fatalf("failed to load CA: %v", err)
	}

	caCertPem, err := os.ReadFile("root-ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPem)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs: caCertPool,
		// ClientAuth: tls.RequireAndVerifyClientCert,
		ClientAuth: tls.NoClientCert,
	}

	// Create a Server instance to listen on port 15001 with the TLS config
	server := &http.Server{
		Addr:      ":15000",
		TLSConfig: tlsConfig,
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, "only POST allowed")
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB limit
		if err != nil {
			httpError(w, http.StatusBadRequest, "failed to read body: %v", err)
			return
		}

		var bodyjson CSRData

		log.Printf("Parsing for csr")
		csr, err := parseCSR(body)
		if err != nil {
			log.Printf("Parsing for json")
			err := json.Unmarshal(body, &bodyjson)

			fmt.Printf("%s\n", body)
			if err != nil {
				log.Println(err)
				httpError(w, http.StatusBadRequest, "invalid request")
				return
			}

			pk, err := hex.DecodeString(bodyjson.PublicKey)
			if err != nil {
				httpError(w, http.StatusBadRequest, "public key is not valid hex")
				return
			}

			ECPubKey, err := ecdh.P256().NewPublicKey(pk)
			if err != nil {
				httpError(w, http.StatusBadRequest, "public key is invalid")
				return
			}

			csr = &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   bodyjson.Subject.CommonName,
					Country:      []string{bodyjson.Subject.Country},
					Province:     []string{bodyjson.Subject.State},
					Locality:     []string{bodyjson.Subject.Locality},
					Organization: []string{bodyjson.Subject.Organization},
				},
				IPAddresses: []net.IP{net.ParseIP(bodyjson.IPAddress)},
				DNSNames:    []string{},
				PublicKey:   ECPubKey,
			}
		} else {
			if err := csr.CheckSignature(); err != nil {
				httpError(w, http.StatusBadRequest, "CSR signature invalid: %v", err)
				return
			}
		}

		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			httpError(w, http.StatusInternalServerError, "failed to create serial: %v", err)
			return
		}

		now := time.Now()
		tmpl := x509.Certificate{
			SerialNumber: serial,
			Subject:      csr.Subject,
			NotBefore:    now.Add(-5 * time.Minute),
			NotAfter:     now.Add(time.Duration(*validDays) * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			IsCA:         false,

			BasicConstraintsValid: true,
		}

		// copy SANs
		tmpl.DNSNames = csr.DNSNames
		tmpl.EmailAddresses = csr.EmailAddresses
		tmpl.IPAddresses = csr.IPAddresses
		// copy any extra extensions - not always safe but preserves request intent
		tmpl.ExtraExtensions = csr.Extensions

		certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, csr.PublicKey, caKey)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "failed to sign certificate: %v", err)
			return
		}

		// Respond with PEM encoded cert
		w.Header().Set("Content-Type", "application/x-pem-file")
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	}

	renewHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, "only POST allowed")
			return
		}

		log.Printf("received renewal request from %s", r.RemoteAddr)

		body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
		if err != nil {
			httpError(w, http.StatusBadRequest, "failed to read body: %v", err)
			return
		}

		cert, err := parseCertificate(body)
		if err != nil {
			httpError(w, http.StatusBadRequest, "invalid certificate: %v", err)
			return
		}

		// Verify the certificate was issued by this CA.
		if err := cert.CheckSignatureFrom(caCert); err != nil {
			httpError(w, http.StatusBadRequest, "certificate not issued by this CA: %v", err)
			return
		}

		// Reject if the certificate has been revoked.
		serialHex := fmt.Sprintf("%x", cert.SerialNumber)
		var revoked bool
		err = db.QueryRow(context.Background(),
			"SELECT EXISTS(SELECT 1 FROM revoked_certificates WHERE serial_number = $1)", serialHex).Scan(&revoked)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "failed to check revocation status: %v", err)
			return
		}
		if revoked {
			httpError(w, http.StatusForbidden, "certificate %s has been revoked", serialHex)
			return
		}

		// Issue a new certificate with the same subject and SANs.
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			httpError(w, http.StatusInternalServerError, "failed to create serial: %v", err)
			return
		}

		now := time.Now()
		tmpl := x509.Certificate{
			SerialNumber:          serial,
			Subject:               cert.Subject,
			NotBefore:             now.Add(-5 * time.Minute),
			NotAfter:              now.Add(time.Duration(*validDays) * 24 * time.Hour),
			KeyUsage:              cert.KeyUsage,
			ExtKeyUsage:           cert.ExtKeyUsage,
			IsCA:                  false,
			BasicConstraintsValid: true,
			DNSNames:              cert.DNSNames,
			EmailAddresses:        cert.EmailAddresses,
			IPAddresses:           cert.IPAddresses,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, cert.PublicKey, caKey)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "failed to sign renewed certificate: %v", err)
			return
		}

		log.Printf("renewed certificate: old serial=%s new serial=%x subject=%s",
			serialHex, serial, cert.Subject.CommonName)

		w.Header().Set("Content-Type", "application/x-pem-file")
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	}

	revokeHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, "only POST allowed")
			return
		}

		log.Printf("received revoke request from %s", r.RemoteAddr)

		body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
		if err != nil {
			httpError(w, http.StatusBadRequest, "failed to read body: %v", err)
			return
		}

		var req RevokeRequest
		if err := json.Unmarshal(body, &req); err != nil {
			httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
			return
		}

		var serialHex string
		if req.Certificate != "" {
			// Extract serial from the provided PEM certificate.
			cert, err := parseCertificate([]byte(req.Certificate))
			if err != nil {
				httpError(w, http.StatusBadRequest, "invalid certificate: %v", err)
				return
			}
			if err := cert.CheckSignatureFrom(caCert); err != nil {
				httpError(w, http.StatusBadRequest, "certificate not issued by this CA: %v", err)
				return
			}
			serialHex = fmt.Sprintf("%x", cert.SerialNumber)
		} else if req.SerialNumber != "" {
			// Validate that the serial number is valid hex.
			if _, ok := new(big.Int).SetString(req.SerialNumber, 16); !ok {
				httpError(w, http.StatusBadRequest, "serial_number is not valid hex")
				return
			}
			serialHex = strings.ToLower(req.SerialNumber)
		} else {
			httpError(w, http.StatusBadRequest, "must provide serial_number or certificate")
			return
		}

		result, err := db.Exec(context.Background(),
			"INSERT INTO revoked_certificates (serial_number, reason) VALUES ($1, $2) ON CONFLICT (serial_number) DO NOTHING",
			serialHex, req.Reason)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "failed to revoke certificate: %v", err)
			return
		}
		rows := result.RowsAffected()
		if rows == 0 {
			httpError(w, http.StatusConflict, "certificate %s is already revoked", serialHex)
			return
		}

		log.Printf("revoked certificate: serial=%s reason=%s", serialHex, req.Reason)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":        "revoked",
			"serial_number": serialHex,
		})
	}

	revokedListHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, "only GET allowed")
			return
		}

		rows, err := db.Query(context.Background(),
			"SELECT serial_number, revoked_at, COALESCE(reason, '') FROM revoked_certificates ORDER BY revoked_at DESC")
		if err != nil {
			httpError(w, http.StatusInternalServerError, "failed to query revoked certificates: %v", err)
			return
		}
		defer rows.Close()

		entries := make([]RevokedEntry, 0)
		for rows.Next() {
			var entry RevokedEntry
			if err := rows.Scan(&entry.SerialNumber, &entry.RevokedAt, &entry.Reason); err != nil {
				httpError(w, http.StatusInternalServerError, "failed to scan row: %v", err)
				return
			}
			entries = append(entries, entry)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}

	http.HandleFunc("/sign", handler)
	http.HandleFunc("/renew", renewHandler)
	http.HandleFunc("/revoke", revokeHandler)
	http.HandleFunc("/revoked", revokedListHandler)
	log.Printf("listening on %s, CA=%s", *addr, *caCertPath)
	log.Fatal(server.ListenAndServeTLS("ca_server.crt", "ca_server.key"))
}

func httpError(w http.ResponseWriter, status int, format string, a ...interface{}) {
	w.WriteHeader(status)
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(w, msg)
}

func parseCSR(data []byte) (*x509.CertificateRequest, error) {
	// try PEM first
	if p, _ := pem.Decode(data); p != nil {
		if strings.Contains(p.Type, "CERTIFICATE REQUEST") || strings.Contains(p.Type, "NEW CERTIFICATE REQUEST") {
			return x509.ParseCertificateRequest(p.Bytes)
		}
		// maybe the client sent PEM but without proper header
	}

	// try DER directly
	if csr, err := x509.ParseCertificateRequest(data); err == nil {
		return csr, nil
	}

	// try to find PEM block inside (support files with multiple PEM blocks)
	rest := data
	for {
		p, r := pem.Decode(rest)
		if p == nil {
			break
		}
		if strings.Contains(p.Type, "CERTIFICATE REQUEST") || strings.Contains(p.Type, "NEW CERTIFICATE REQUEST") {
			return x509.ParseCertificateRequest(p.Bytes)
		}
		rest = r
	}

	return nil, errors.New("no CSR found in body")
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	p, _ := pem.Decode(data)
	if p != nil && p.Type == "CERTIFICATE" {
		return x509.ParseCertificate(p.Bytes)
	}
	// Try DER directly.
	if cert, err := x509.ParseCertificate(data); err == nil {
		return cert, nil
	}
	return nil, errors.New("no certificate found in body")
}

func loadCA(certPath, keyPath string) (*x509.Certificate, interface{}, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca cert: %w", err)
	}
	p, _ := pem.Decode(certPEM)
	if p == nil || p.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode PEM certificate from %s", certPath)
	}
	caCert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca key: %w", err)
	}
	kBlock, _ := pem.Decode(keyPEM)
	if kBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM private key from %s", keyPath)
	}

	var priv interface{}
	switch kBlock.Type {
	case "RSA PRIVATE KEY":
		priv, err = x509.ParsePKCS1PrivateKey(kBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse rsa key: %w", err)
		}
	case "EC PRIVATE KEY":
		priv, err = x509.ParseECPrivateKey(kBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse ec key: %w", err)
		}
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(kBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse pkcs8 key: %w", err)
		}
		switch parsed := parsed.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			priv = parsed
		default:
			return nil, nil, fmt.Errorf("unsupported private key type in PKCS#8: %T", parsed)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported private key type: %s", kBlock.Type)
	}

	return caCert, priv, nil
}
