CREATE TABLE IF NOT EXISTS quarantined_files (
  id BIGSERIAL PRIMARY KEY,
  sample_hash TEXT NOT NULL,
  filename TEXT NOT NULL,
  original_path TEXT NOT NULL,
  verdict_label TEXT NOT NULL,
  confidence REAL NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')) DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_at TIMESTAMPTZ
);

GRANT SELECT, INSERT, UPDATE ON quarantined_files TO {{ROLE_NAME}};
GRANT USAGE ON SEQUENCE quarantined_files_id_seq TO {{ROLE_NAME}};
