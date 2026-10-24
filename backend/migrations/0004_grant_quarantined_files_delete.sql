-- 0003 granted SELECT/INSERT/UPDATE but not DELETE on quarantined_files.
-- Unlike audit_log, there's no tamper-evidence reason to withhold DELETE
-- here -- it's ordinary operational state (e.g. clearing old decided
-- entries), and withholding it only broke legitimate cleanup with no
-- security benefit.
GRANT DELETE ON quarantined_files TO {{ROLE_NAME}};
