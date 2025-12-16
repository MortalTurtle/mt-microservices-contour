package main

import (
	"gocommon/httpclient"
	"io"
	"log"
	"time"
)

func main() {
	cfg := httpclient.DefaultConfig()

	client, err := httpclient.NewClient(cfg)
	if err != nil {
		log.Fatalf("Unable to create client : %v", err)
	}

	time.Sleep(4 * time.Second)
	resp, err := client.Get("https://service1.mt.ru/ping")
	if err != nil {
		log.Printf("Ping failed: %v", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
		return
	}

	log.Printf("Response body: %s", string(body))
}
