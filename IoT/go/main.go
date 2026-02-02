package main

// https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	// "database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"time"

	// "strings"

	"errors"
	"os"
	"path"

	_ "modernc.org/sqlite"
)

type Payload struct {
	Temp float64 `json:"temp"`
	Time string  `json:"time"`
}

func loadCertificate(basePath string) (tls.Certificate, error) {
	certFile := path.Join(basePath, "client.crt")
	keyFile := path.Join(basePath, "client.key")

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

func main() {
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
		MinVersion:   tls.VersionTLS12,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	min, max := 15.00, 20.00
	var temp float64

	var start time.Time

	interval := time.Now()

	for range ticker.C {
		// 5 seconds sending, 5 seconds pause loop
		if time.Since(interval) >= 8*time.Second {
			fmt.Println("")
			fmt.Printf("%sPause%s\n", "\033[33m", "\033[0m")
			fmt.Println("")
			time.Sleep(8 * time.Second)
			interval = time.Now()
		}

		temp = min + rand.Float64()*(max-min)

		payload := Payload{
			Temp: temp,
			Time: time.Now().Format(time.RFC3339),
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			log.Printf("JSON marshal error: %v", err)
			continue
		}

		start = time.Now()

		// Create POST request
		reqBody := bytes.NewBuffer(jsonData)
		request, err := http.NewRequest("POST", "https://localhost:8443/data", reqBody)
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
		fmt.Printf("		%sresponse time: %d ms seconds%s\n", "\033[32m", time.Since(start).Milliseconds(), "\033[0m")
	}
}
