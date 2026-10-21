package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

func corpusHandler(verdictEngineURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var resp *http.Response
		var err error
		switch r.Method {
		case http.MethodGet:
			resp, err = httpClient.Get(verdictEngineURL + "/corpus")
		case http.MethodPost:
			resp, err = httpClient.Post(verdictEngineURL+"/corpus", "application/json", r.Body)
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

func corpusDecisionHandler(verdictEngineURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/corpus/")
		parts := strings.Split(path, "/")
		if len(parts) != 2 || (parts[1] != "approve" && parts[1] != "reject") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		contentHash, decision := parts[0], parts[1]
		actor, _ := sessionFromContext(r.Context())
		body, err := json.Marshal(map[string]string{"actor": actor.Username})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		resp, err := httpClient.Post(verdictEngineURL+"/corpus/"+contentHash+"/"+decision, "application/json", bytes.NewReader(body))
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
