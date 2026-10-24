CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  entry_hash TEXT NOT NULL,
  prev_log_hash TEXT NOT NULL,
  data JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_entry_hash_idx ON audit_log (entry_hash);

-- verdict_role can append and read, but never edit or delete a past entry --
-- this is the actual tamper-evidence improvement over the old flat file.
GRANT SELECT, INSERT ON audit_log TO {{ROLE_NAME}};
-- INSERT into a BIGSERIAL column calls nextval() on its backing sequence,
-- which needs its own USAGE grant -- this only lets the role advance the
-- counter, not read/alter audit_log rows, so it doesn't touch the
-- no-UPDATE/DELETE property above.
GRANT USAGE ON SEQUENCE audit_log_id_seq TO {{ROLE_NAME}};
