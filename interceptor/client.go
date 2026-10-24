package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"time"
)

var httpClient = &http.Client{Timeout: 60 * time.Second}

type submitResult struct {
	Decision     string `json:"decision"`
	QuarantineID int64  `json:"quarantine_id,omitempty"`
}

// submit posts the quarantined payload at payloadPath to the backend's
// /api/intercept endpoint, same multipart shape the dashboard's own upload
// uses plus the original_path field the backend needs to report where a
// released file is headed.
func submit(cfg Config, payloadPath, filename, originalPath string) (submitResult, error) {
	var result submitResult

	file, err := os.Open(payloadPath)
	if err != nil {
		return result, fmt.Errorf("open payload: %w", err)
	}
	defer file.Close()

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("sample", filename)
	if err != nil {
		return result, err
	}
	if _, err := io.Copy(part, file); err != nil {
		return result, err
	}
	if err := w.WriteField("original_path", originalPath); err != nil {
		return result, err
	}
	if err := w.Close(); err != nil {
		return result, err
	}

	req, err := http.NewRequest(http.MethodPost, cfg.BackendURL+"/api/intercept", &body)
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return result, fmt.Errorf("backend returned %d: %s", resp.StatusCode, string(b))
	}
	var full struct {
		Decision     string `json:"decision"`
		QuarantineID *int64 `json:"quarantine_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&full); err != nil {
		return result, err
	}
	result.Decision = full.Decision
	if full.QuarantineID != nil {
		result.QuarantineID = *full.QuarantineID
	}
	return result, nil
}

// pollStatus checks a held quarantine entry's current decision.
func pollStatus(cfg Config, quarantineID int64) (string, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/intercept/%d/status", cfg.BackendURL, quarantineID), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("backend returned %d: %s", resp.StatusCode, string(b))
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	return body.Status, nil
}
