-- T-802: delayed start, rolling concurrency cap, and agent check-ins while a job runs
-- (so a cancel reaches running devices and a silent agent is noticed sooner).
ALTER TABLE jobs ADD COLUMN run_at INTEGER;
ALTER TABLE jobs ADD COLUMN max_parallel INTEGER;
ALTER TABLE job_targets ADD COLUMN progress_at INTEGER;
