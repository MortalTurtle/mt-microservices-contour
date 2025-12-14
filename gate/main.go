package main

import (
	"gate/handlers"
	"gocommon/server"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/ping", handlers.PingHandler)

	cfg := server.DefaultConfig()

	server, err := server.NewServer(cfg)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting gate on %s", ":443")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}
