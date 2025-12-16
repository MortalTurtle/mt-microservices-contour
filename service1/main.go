package main

import (
	"gocommon/httpserver"
	"log"
	"net/http"
	"service1/handlers"
)

func main() {
	cfg := httpserver.DefaultConfig()

	server, err := httpserver.NewServer(cfg)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", handlers.PingHandler)

	log.Printf("Starting service1 on :443")

	if err := server.ListenAndServeWithHandler(mux); err != nil {
		log.Fatal(err)
	}
}
