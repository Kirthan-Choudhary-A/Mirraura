package main

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type QuarantinedFile struct {
	ID           int64     `json:"id"`
	SampleHash   string    `json:"sample_hash"`
	Filename     string    `json:"filename"`
	OriginalPath string    `json:"original_path"`
	VerdictLabel string    `json:"verdict_label"`
	Confidence   float64   `json:"confidence"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

func insertQuarantine(ctx context.Context, pool *pgxpool.Pool, sampleHash, filename, originalPath, verdictLabel string, confidence float64) (int64, error) {
	var id int64
	err := pool.QueryRow(ctx,
		`INSERT INTO quarantined_files (sample_hash, filename, original_path, verdict_label, confidence)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		sampleHash, filename, originalPath, verdictLabel, confidence,
	).Scan(&id)
	return id, err
}

func listPendingQuarantine(ctx context.Context, pool *pgxpool.Pool) ([]QuarantinedFile, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, sample_hash, filename, original_path, verdict_label, confidence, status, created_at
		 FROM quarantined_files WHERE status = 'pending' ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	// Never nil: encoding/json marshals a nil slice as "null", which would
	// break the frontend's .length/.map() calls the moment the queue is
	// empty instead of giving it an empty array.
	out := []QuarantinedFile{}
	for rows.Next() {
		var q QuarantinedFile
		if err := rows.Scan(&q.ID, &q.SampleHash, &q.Filename, &q.OriginalPath, &q.VerdictLabel, &q.Confidence, &q.Status, &q.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// decideQuarantine moves id from "pending" to status ("approved" or
// "rejected"), returning the decided row so the caller (the HTTP handler)
// can audit-log and respond with its original_path/filename. Returns
// pgx.ErrNoRows if id doesn't exist or isn't pending (already decided,
// racing with another admin, or a bad id) -- the handler maps that to 404.
func decideQuarantine(ctx context.Context, pool *pgxpool.Pool, id int64, status string) (QuarantinedFile, error) {
	var q QuarantinedFile
	err := pool.QueryRow(ctx,
		`UPDATE quarantined_files SET status = $1, decided_at = now()
		 WHERE id = $2 AND status = 'pending'
		 RETURNING id, sample_hash, filename, original_path, verdict_label, confidence, status, created_at`,
		status, id,
	).Scan(&q.ID, &q.SampleHash, &q.Filename, &q.OriginalPath, &q.VerdictLabel, &q.Confidence, &q.Status, &q.CreatedAt)
	return q, err
}

func getQuarantineStatus(ctx context.Context, pool *pgxpool.Pool, id int64) (string, error) {
	var status string
	err := pool.QueryRow(ctx, `SELECT status FROM quarantined_files WHERE id = $1`, id).Scan(&status)
	if err != nil {
		return "", fmt.Errorf("quarantine %d: %w", id, err)
	}
	return status, nil
}
