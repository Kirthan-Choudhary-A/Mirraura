DO $$ BEGIN
  EXECUTE 'CREATE ROLE {{ROLE_NAME}} LOGIN PASSWORD ''{{ROLE_PASSWORD}}''';
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS known_bad_hashes (
  hash TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
  source TEXT NOT NULL,
  proposed_at TIMESTAMPTZ NOT NULL,
  reviewed_at TIMESTAMPTZ
);

GRANT SELECT, INSERT, UPDATE, DELETE ON known_bad_hashes TO {{ROLE_NAME}};
