package main

import (
	"io"
	"net/http"
	"strings"
)

func hashesHandler(verdictEngineURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var resp *http.Response
		var err error
		switch r.Method {
		case http.MethodGet:
			resp, err = http.Get(verdictEngineURL + "/hashes")
		case http.MethodPost:
			resp, err = httpClient.Post(verdictEngineURL+"/hashes", "application/json", r.Body)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err != nil {
			http.Error(w, "verdict-engine unreachable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

func hashDecisionHandler(verdictEngineURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/hashes/")
		parts := strings.Split(path, "/")
		if len(parts) != 2 || (parts[1] != "approve" && parts[1] != "reject") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		hash, decision := parts[0], parts[1]
		resp, err := httpClient.Post(verdictEngineURL+"/hashes/"+hash+"/"+decision, "application/json", nil)
		if err != nil {
			http.Error(w, "verdict-engine unreachable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}
