CREATE TABLE IF NOT EXISTS known_bad_samples (
  content_hash TEXT PRIMARY KEY,  -- sha256 hex of `content`
  content BYTEA NOT NULL,
  label TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
  source TEXT NOT NULL,
  proposed_at TIMESTAMPTZ NOT NULL,
  reviewed_at TIMESTAMPTZ
);

GRANT SELECT, INSERT, UPDATE, DELETE ON known_bad_samples TO {{ROLE_NAME}};

-- The two samples previously hardcoded as files in known_bad_samples/, so a
-- fresh install's similarity demo works without manual setup -- same idea as
-- 0001's EICAR seed.
INSERT INTO known_bad_samples (content_hash, content, label, status, source, proposed_at, reviewed_at)
SELECT encode(sha256(c), 'hex'), c, l, 'approved', 'manual', now(), now()
FROM (
  VALUES
    (convert_to(E'#!/bin/bash\ntouch /etc/mirraura-test-marker\ncat /etc/hostname > /dev/null\n', 'UTF8'), 'sensitive_write'),
    (convert_to(E'#!/bin/bash\nexec 3<>/dev/tcp/127.0.0.1/31337 2>/dev/null || true\n', 'UTF8'), 'devtcp_reverse_shell')
) AS seed(c, l)
ON CONFLICT (content_hash) DO NOTHING;
