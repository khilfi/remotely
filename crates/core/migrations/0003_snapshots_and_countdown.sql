-- Milestone 2: snapshots and approvals.

-- VM-05: the name of the safety snapshot taken on this target before the action ran, if one was.
-- Kept even when the action then failed, since the snapshot is on the VM either way.
ALTER TABLE job_targets ADD COLUMN safety_snapshot TEXT;

-- AP-03: when the job's countdown ends (RFC 3339 UTC), so Activity can show the time left and the
-- cancel button for as long as it lasts.
ALTER TABLE jobs ADD COLUMN countdown_until TEXT;
