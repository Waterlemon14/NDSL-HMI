package main

// https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	// "time"

	"errors"
	"os"
	"path"

	_ "modernc.org/sqlite"
)

type Payload struct {
	Temp int    `json:"temp"`
	Time string `json:"time"`
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
	db, err := initDB("data.db")
	if err != nil {
		log.Fatalf("DB init error: %v", err)
	}
	defer db.Close()

	http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		dataHandler(w, r, db)
	})
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
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAPool,
		MinVersion:   tls.VersionTLS13,
	}

	server := &http.Server{
		Addr:        ":8443",
		TLSConfig:   tlsConfig,
		IdleTimeout: 4 * time.Second,
	}

	// http.HandleFunc("/ping", handlePing)

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		panic("Server failed to start")
	}
}

func dataHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// Log and echo back the data
	var p Payload
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Insert into SQLite
	_, err = db.Exec(`INSERT INTO received_data (client_timestamp, temp) VALUES (?, ?)`, p.Time, p.Temp)
	if err != nil {
		http.Error(w, "Database insert failed", http.StatusInternalServerError)
		return
	}

	log.Printf("Stored data: Time=%s, Temp=%q\n", p.Time, p.Temp)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"stored","client_timestamp":%s,"temp":%q}`, p.Time, p.Temp)

}

func initDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS received_data (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		temp TEXT,
		client_timestamp TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = db.Exec(createTable)
	if err != nil {
		return nil, err
	}

	return db, nil
}
