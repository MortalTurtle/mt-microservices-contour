package main

import (
	"gate/handlers"
	"github.com/mtproject/gocommon/certclient"
	"log"
	"net/http"
	"os"
)

func main() {
	serviceCN := os.Getenv("SERVICE_CN")
	serviceIP := os.Getenv("SERVICE_IP")
	certServiceURL := os.Getenv("CERTSERVICE_URL")

	client := certclient.NewClient(certServiceURL, true)

	caData, err := client.GetCA()
	if err != nil {
		log.Printf("Warning: Failed to get CA: %v", err)
	} else {
		if err := os.WriteFile("/certs/ca.crt", caData, 0644); err != nil {
			log.Printf("Warning: Failed to save CA: %v", err)
		}
	}

	cert, err := client.RequestCertificate(
		serviceCN,
		[]string{serviceIP, "127.0.0.1", "::1"},
		[]string{
			serviceCN,
			"localhost",
		},
		"720h",
	)
	if err != nil {
		log.Fatalf("Failed to request certificate: %v", err)
	}

	basePath := "/certs/gate"
	if err := certclient.SaveToFile(cert, basePath); err != nil {
		log.Fatalf("Failed to save certificate: %v", err)
	}

	tlsConfig, err := certclient.LoadTLSConfig(
		basePath+".crt",
		basePath+".key",
		basePath+"-ca.crt",
		true,
	)
	if err != nil {
		log.Fatalf("Failed to load TLS config: %v", err)
	}

	http.HandleFunc("/ping", handlers.PingHandler)

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	log.Printf("Starting gate on %s", ":8443")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}
