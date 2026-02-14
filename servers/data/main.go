package main

// https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"errors"
	"os"
	"path"

	_ "modernc.org/sqlite"
)

type Payload struct {
	Temp float64 `json:"temp"`
	Time string  `json:"time"`
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
	dataDB, err := initDB("data.db")
	if err != nil {
		log.Fatalf("DB init error: %v", err)
		return
	}
	defer dataDB.Close()

	raDB, err := sql.Open("sqlite", "../ra/db.sqlite3")
	if err != nil {
		log.Fatalf("RA DB open error: %v", err)
		return
	}
	defer raDB.Close()

	const BASE_PATH = "."

	cert, err := loadCertificate(BASE_PATH)
	if err != nil {
		panic(err.Error())
	}

	rootCAPool, err := loadCertPool(BASE_PATH)
	if err != nil {
		panic(err.Error())
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

	http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		dataHandler(w, r, dataDB, raDB)
	})
	http.HandleFunc("/ping", handlePing)

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		panic("Server failed to start")
	}
}

func dataHandler(w http.ResponseWriter, r *http.Request, dataDB *sql.DB, raDB *sql.DB) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract the MAC from the Common Name (CN) in the subject
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "Client certificate required", http.StatusBadRequest)
		return
	}
	clientCert := r.TLS.PeerCertificates[0]
	mac := clientCert.Subject.CommonName

	deviceState, err := checkDeviceState(raDB, mac)
	if err != nil {
		log.Printf("Checking device state error %s: %v", mac, err)
		http.Error(w, "Device Suspended: Reconnect", http.StatusConflict)
		return
	}

	if deviceState == StateSuspended {
		http.Error(w, "Device Suspended: Reconnect", http.StatusConflict)
		return
	}
	if deviceState == StateReconnecting {
		if err := reconnectDevice(w, mac); err != nil {
			log.Printf("Error reconnecting check for MAC %s: %v", mac, err)
			http.Error(w, "Reconnecting error", http.StatusInternalServerError)
			return
		}
	}

	if anomaly, err := isAnomaly(w, dataDB, mac); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	} else if anomaly {
		if err := suspendDevice(w, mac); err != nil {
			http.Error(w, "Failed to suspend device", http.StatusInternalServerError)
			return
		}
	}

	// Assume connected already

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

	// Insert into SQLite
	_, err = dataDB.Exec(`
		INSERT INTO received_data (mac, client_timestamp, temp) 
		VALUES (?, ?, ?)`,
		mac, p.Time, p.Temp,
	)

	if err != nil {
		http.Error(w, "Database insert failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

}

func initDB(path string) (*sql.DB, error) {
	dataDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS received_data (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mac TEXT,
		temp TEXT,
		client_timestamp TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = dataDB.Exec(createTable)
	if err != nil {
		return nil, err
	}

	return dataDB, nil
}

func checkDeviceState(raDB *sql.DB, mac string) (DeviceState, error) {
	var state string
	err := raDB.QueryRow(`
		SELECT state
		FROM idverification_device
		WHERE mac = ?
		LIMIT 1`,
		mac,
	).Scan(&state)

	if err != nil {
		log.Printf("RA DB query error: %v", err)
		return DeviceState(""), err
	}
	return DeviceState(state), nil
}

func reconnectDevice(w http.ResponseWriter, mac string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	reconnectURL := fmt.Sprintf("http://localhost:8000/reconnect/%s/", mac)

	req, err := http.NewRequest("GET", reconnectURL, nil)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Reconnect request failed: %v", err)
		http.Error(w, "Reconnect upstream unreachable", http.StatusBadGateway)
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read reconnect response body: %v", err)
		return err
	}
	fmt.Println(string(body))

	http.Error(w, "Anomaly detected; device reported", http.StatusConflict)
	return nil
}

func suspendDevice(w http.ResponseWriter, mac string) error {
	fmt.Printf("%sThe variable time exceeds the calculated limit.%s\n", "\033[33m", "\033[0m")
	client := &http.Client{Timeout: 10 * time.Second}
	payload := Report{
		MAC:     mac,
		Anomaly: "disconnected",
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return err
	}
	reqBody := bytes.NewBuffer(jsonData)
	req, err := http.NewRequest("POST", "http://localhost:8000/report/", reqBody)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Report request failed: %v", err)
		http.Error(w, "Anomaly reported but upstream unreachable", http.StatusBadGateway)
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read report response body: %v", err)
	} else {
		fmt.Println(string(body))
	}

	http.Error(w, "Anomaly detected; device reported", http.StatusConflict)
	return nil
}

func isAnomaly(w http.ResponseWriter, dataDB *sql.DB, mac string) (bool, error) {
	var lastCreatedAt time.Time
	err := dataDB.QueryRow(`
		SELECT created_at
		FROM received_data 
		WHERE mac = ? 
		ORDER BY created_at DESC 
		LIMIT 1`,
		mac,
	).Scan(&lastCreatedAt)

	if err == sql.ErrNoRows {
		// First time seeing this MAC: no previous activity, so no anomaly
		return false, nil
	} else if err != nil {
		log.Printf("Error: %v", err)
		http.Error(w, "Server Database error", http.StatusInternalServerError)
		return false, err
	}

	now := time.Now()
	disconnectTime := lastCreatedAt.Add(10 * time.Second)
	return now.After(disconnectTime), nil
}
