package main

import (
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
)

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
	caCertPath := flag.String("ca-cert", "ca.crt", "Path to CA certificate (PEM)")
	caKeyPath := flag.String("ca-key", "ca.key", "Path to CA private key (PEM, PKCS#1, PKCS#8 or EC)")
	addr := flag.String("addr", ":15000", "HTTP listen address")
	validDays := flag.Int("days", 365, "Validity of issued certs in days")
	flag.Parse()

	caCert, caKey, err := loadCA(*caCertPath, *caKeyPath)
	if err != nil {
		log.Fatalf("failed to load CA: %v", err)
	}

	caCertPem, err := os.ReadFile("ca.crt")
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

		csr, err := parseCSR(body)
		if err != nil {
			err := json.Unmarshal(body, &bodyjson)
			if err != nil {
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

	http.HandleFunc("/sign", handler)
	log.Printf("listening on %s, CA=%s", *addr, *caCertPath)
	log.Fatal(server.ListenAndServeTLS("ca_server.crt", "ca_server_private.key"))
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
