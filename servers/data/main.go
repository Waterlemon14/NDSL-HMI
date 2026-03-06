package main

// https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

type Payload struct {
	Temp float64 `json:"temp"`
	Time string  `json:"time"`
	MAC  string  `json:"MAC"`
}

type Report struct {
	MAC     string `json:"mac"`
	Anomaly string `json:"anomaly"`
}

// Device state constants (must match Django idverification.models.State)
const (
	StateConnected    = "connected"
	StateReconnecting = "reconnecting"
	StateSuspended    = "suspended"
	StateRevoked      = "revoked"
)

type DeviceState string

func (s DeviceState) IsValid() bool {
	switch s {
	case StateConnected, StateReconnecting, StateSuspended:
		return true
	default:
		return false
	}
}

// db is the connection pool to the Supabase Postgres database.
var db *pgxpool.Pool

// raClient is an HTTP client configured to trust the root CA for calls to the RA server.
var raClient *http.Client

// initDB connects to Postgres and ensures the received_data table exists.
func initDB(databaseURL string) error {
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		return fmt.Errorf("failed to create connection pool: %w", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}
	_, err = pool.Exec(context.Background(), `
	CREATE TABLE IF NOT EXISTS received_data (
		id SERIAL PRIMARY KEY,
		mac TEXT,
		temp DOUBLE PRECISION,
		client_timestamp TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return fmt.Errorf("failed to create received_data table: %w", err)
	}
	log.Println("connected to database and ensured received_data table exists")
	db = pool
	return nil
}

func loadCertificate(basePath string) (tls.Certificate, error) {
	certFile := path.Join(basePath, "server.crt")
	keyFile := path.Join(basePath, "server.key")

	return tls.LoadX509KeyPair(certFile, keyFile)
}

func loadCertPool(basePath string) (*x509.CertPool, error) {
	rootCAFile := path.Join(basePath, "root-ca.crt")

	certBytes, err := os.ReadFile(rootCAFile)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(certBytes)
	if !ok {
		return nil, errors.New("Could not append root certificate to pool")
	}

	return certPool, nil
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	message := string(reqBody)
	response := struct {
		RequestMessage  string `json:"requestMessage"`
		ResponseMessage string `json:"responseMessage"`
	}{
		RequestMessage:  message,
		ResponseMessage: "pong",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Printf("warning: could not load .env file: %v", err)
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}
	var err error
	err = initDB(databaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	const BASE_PATH = "."

	cert, err := loadCertificate(BASE_PATH)
	if err != nil {
		panic(err.Error())
	}

	rootCAPool, err := loadCertPool(BASE_PATH)
	if err != nil {
		panic(err.Error())
	}

	raClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAPool,
			},
		},
	}

	tlsConfig := &tls.Config{
		Certificates:           []tls.Certificate{cert},
		RootCAs:                rootCAPool,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              rootCAPool,
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
	}

	server := &http.Server{
		Addr:        ":8443",
		TLSConfig:   tlsConfig,
		IdleTimeout: 4 * time.Second,
	}

	http.HandleFunc("/data", dataHandler)
	http.HandleFunc("/ping", handlePing)

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		panic("Server failed to start")
	}
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract the MAC from the Common Name (CN) in the subject
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "Client certificate required", http.StatusBadRequest)
		return
	}
	// clientCert := r.TLS.PeerCertificates[0]
	// mac := clientCert.Subject.CommonName

	// Parsing data
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	var p Payload
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	mac := p.MAC

	deviceState, err := checkDeviceState(mac)
	if err != nil {
		log.Printf("Checking device state error %s: %v", mac, err)
		// http.Error(w, "Checking device state error", http.StatusConflict)
		return
	}

	switch deviceState {
	case StateRevoked:
		log.Printf("Device Revoked")

		// http.Error(w, "Device Suspended: Reconnect", http.StatusConflict)
		return
	case StateSuspended:
		log.Printf("Device Suspended: Reconnect")

		// http.Error(w, "Device Suspended: Reconnect", http.StatusConflict)
		return
	case StateReconnecting:
		if err := reconnectDevice(mac); err != nil {
			log.Printf("Error reconnecting check for MAC %s: %v", mac, err)
			// http.Error(w, "Reconnecting error", http.StatusInternalServerError)
			return
		}

	default:
		if anomaly, err := isAnomaly(mac); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		} else if anomaly {
			if err := suspendDevice(mac); err != nil {
				http.Error(w, "Failed to suspend device", http.StatusInternalServerError)
				return
			}
		}
	}

	// Assume connected

	// Insert into PostgreSQL
	_, err = db.Exec(context.Background(),
		"INSERT INTO received_data (mac, client_timestamp, temp) VALUES ($1, $2, $3)",
		mac, p.Time, p.Temp)
	if err != nil {
		log.Printf("Database insert failed: %s", err)
		// http.Error(w, "Database insert failed", http.StatusInternalServerError)
		return
	}
	// log.Printf("Logged: %s", p.Time)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

}

func checkDeviceState(mac string) (DeviceState, error) {
	var state string
	err := db.QueryRow(context.Background(),
		"SELECT state FROM idverification_device WHERE mac = $1 LIMIT 1", mac).Scan(&state)

	log.Printf("state (%s)", state)

	if err != nil {
		log.Printf("RA DB query error for MAC (%s) :  %v", mac, err)
		return DeviceState(""), err
	}
	return DeviceState(state), nil
}

func reconnectDevice(mac string) error {
	reconnectURL := fmt.Sprintf("https://localhost:8000/reconnect/%s/", mac)

	req, err := http.NewRequest("GET", reconnectURL, nil)
	if err != nil {
		// http.Error(w, "Internal error", http.StatusInternalServerError)
		return err
	}
	resp, err := raClient.Do(req)
	if err != nil {
		log.Printf("Reconnect request failed: %v", err)
		// http.Error(w, "Reconnect upstream unreachable", http.StatusBadGateway)
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read reconnect response body: %v", err)
		return err
	}
	fmt.Println(string(body))

	// http.Error(w, "Reconnecting Device", http.StatusConflict)
	return nil
}

func suspendDevice(mac string) error {
	fmt.Printf("%sThe variable time exceeds the calculated limit.%s\n", "\033[33m", "\033[0m")
	payload := Report{
		MAC:     mac,
		Anomaly: "disconnected",
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		// http.Error(w, "Internal error", http.StatusInternalServerError)
		return err
	}
	reqBody := bytes.NewBuffer(jsonData)
	req, err := http.NewRequest("POST", "https://localhost:8000/report/", reqBody)
	if err != nil {
		log.Printf("Request body read error: %v", err)
		// http.Error(w, "Internal error", http.StatusInternalServerError)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := raClient.Do(req)
	if err != nil {
		log.Printf("Report request failed: %v", err)
		// http.Error(w, "Anomaly reported but upstream unreachable", http.StatusBadGateway)
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read report response body: %v", err)
	} else {
		fmt.Println(string(body))
	}

	// http.Error(w, "Suspending Device", http.StatusConflict)
	return nil
}

func isAnomaly(mac string) (bool, error) {
	var lastCreatedAt time.Time
	err := db.QueryRow(context.Background(),
		"SELECT created_at FROM received_data WHERE mac = $1 ORDER BY created_at DESC LIMIT 1",
		mac).Scan(&lastCreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		// First time seeing this MAC: no previous activity, so no anomaly
		return false, nil
	} else if err != nil {
		log.Printf("Error querying anomaly for MAC %s: %v", mac, err)
		return false, err
	}

	now := time.Now()
	disconnectTime := lastCreatedAt.Add(10 * time.Second)

	return now.After(disconnectTime), nil
}
