-- Milestone 5: bulk execution (BX-01 to BX-07).

-- BX-02: what each host printed on stderr (`output` holds stdout), capped like stdout.
ALTER TABLE job_targets ADD COLUMN stderr TEXT;

-- BX-02: bytes each stream sent before the cap. The stored text keeps the start and the end of a
-- longer output, and `output_truncated` says that the middle was cut.
ALTER TABLE job_targets ADD COLUMN stdout_bytes INTEGER;
ALTER TABLE job_targets ADD COLUMN stderr_bytes INTEGER;
ALTER TABLE job_targets ADD COLUMN output_truncated INTEGER NOT NULL DEFAULT 0 CHECK (output_truncated IN (0, 1));

-- BX-03: SHA-256 over the whole of stdout and stderr, exactly and with trailing whitespace ignored, so
-- hosts group correctly even when their stored output was cut. Taken after vault secrets were scrubbed.
ALTER TABLE job_targets ADD COLUMN output_hash TEXT;
ALTER TABLE job_targets ADD COLUMN output_hash_loose TEXT;

-- BX-03: why a host failed before or around its command (CoreError::code), so failures group by cause.
ALTER TABLE job_targets ADD COLUMN error_code TEXT;

-- BX-04: retries point at the job they retry (jobs.retry_of, from the first schema).
CREATE INDEX jobs_by_retry ON jobs (retry_of);

-- BX-01: the VM a session reaches (sessions.vm_id, from the first schema), looked up per VM.
CREATE INDEX sessions_by_vm ON sessions (workspace_id, vm_id);
