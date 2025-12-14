package main

import (
	"gate/handlers"
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", handlers.PingHandler)
	log.Fatal(http.ListenAndServe(":80", mux))
}
