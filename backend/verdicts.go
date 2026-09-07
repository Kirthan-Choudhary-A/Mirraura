package main

import (
	"io"
	"net/http"
	"strings"
)

func verdictsListHandler(verdictEngineURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(verdictEngineURL + "/verdicts")
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

func verdictDetailHandler(verdictEngineURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/verdicts/")
		resp, err := http.Get(verdictEngineURL + "/verdicts/" + id)
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
