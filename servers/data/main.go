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
		dataHandler(w, r, db)
	})
	http.HandleFunc("/ping", handlePing)

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

	// Extract the MAC from the Common Name (CN) in the subject
	clientCert := r.TLS.PeerCertificates[0]
	MAC := clientCert.Subject.CommonName

	// Anomaly detection
	var lastCreatedAt time.Time
	err := db.QueryRow(`
		SELECT created_at
		FROM received_data 
		WHERE mac = ? 
		ORDER BY created_at DESC 
		LIMIT 1`,
		MAC,
	).Scan(&lastCreatedAt)

	// log.Printf("%s%s%s", "\033[33m", lastCreatedAt, "\033[0m")

	if err == sql.ErrNoRows {
		log.Printf("Error")
	}

	now := time.Now()
	disconnectTime := lastCreatedAt.Add(5 * time.Second)

	if now.After(disconnectTime) {
		fmt.Printf("%sThe variable time exceeds the calculated limit.%s\n", "\033[33m", "\033[33m")

		// ping server
		//

		client := &http.Client{}

		payload := Report{
			MAC:     MAC,
			Anomaly: "disconnect",
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			log.Printf("JSON marshal error: %v", err)
			for {
			}
		}

		reqBody := bytes.NewBuffer(jsonData)
		request, err := http.NewRequest("POST", "http://localhost:8000/report/", reqBody)
		if err != nil {
			panic(err.Error())
		}

		response, err := client.Do(request)
		if err != nil {
			panic(err.Error())
		}
		defer response.Body.Close()

		body, err := io.ReadAll(response.Body)
		if err != nil {
			panic(err.Error())
		}

		fmt.Println(string(body))

		return
	}

	// Parsing data
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
	_, err = db.Exec(`
		INSERT INTO received_data (mac, client_timestamp, temp) 
		VALUES (?, ?, ?)`,
		MAC, p.Time, p.Temp,
	)

	if err != nil {
		http.Error(w, "Database insert failed", http.StatusInternalServerError)
		return
	}

	// log.Printf("Stored data: Time=%s, Temp=%q\n", p.Time, p.Temp)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// fmt.Fprintf(w, `{"status":"stored","client_timestamp":%s,"temp":%q}`, p.Time, p.Temp)

}

func initDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
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
	_, err = db.Exec(createTable)
	if err != nil {
		return nil, err
	}

	return db, nil
}
