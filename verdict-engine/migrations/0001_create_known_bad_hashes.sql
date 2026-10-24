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

-- Reference fixture for the documented demo (upload the EICAR test file, see
-- samples/EICAR.md, and watch it short-circuit to Compromised) so it works on
-- a fresh install.
INSERT INTO known_bad_hashes (hash, label, status, source, proposed_at, reviewed_at)
VALUES (
  '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
  'EICAR-Test-File',
  'approved',
  'manual',
  now(),
  now()
)
ON CONFLICT (hash) DO NOTHING;
