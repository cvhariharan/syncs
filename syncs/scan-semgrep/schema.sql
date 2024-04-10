CREATE TABLE IF NOT EXISTS semgrep_repo_scans (
    repo_id uuid PRIMARY KEY REFERENCES repos(id) ON DELETE CASCADE ON UPDATE RESTRICT,
    results jsonb NOT NULL,
    _mergestat_synced_at timestamp with time zone NOT NULL DEFAULT now()
);
COMMENT ON TABLE semgrep_repo_scans IS 'Table of semgrep repo scans';
COMMENT ON COLUMN semgrep_repo_scans.repo_id IS 'foreign key for public.repos.id';
COMMENT ON COLUMN semgrep_repo_scans.results IS 'JSON results from semgrep repo scan';
COMMENT ON COLUMN semgrep_repo_scans._mergestat_synced_at IS 'timestamp when record was synced into the MergeStat database';

DROP VIEW IF EXISTS semgrep_repo_vulnerabilities;
CREATE VIEW semgrep_repo_vulnerabilities AS  SELECT semgrep_repo_scans.repo_id,
    r.value ->> 'check_id'::text AS check_id,
    r.value ->> 'path'::text AS path,
    (r.value -> 'end'::text) ->> 'col'::text AS location_col,
    (r.value -> 'end'::text) ->> 'line'::text AS location_line,
    (r.value -> 'end'::text) ->> 'offset'::text AS location_offset,
    (r.value -> 'extra'::text) ->> 'message'::text AS details,
    (r.value -> 'extra'::text) ->> 'severity'::text AS severity,
    (r.value -> 'extra'::text) -> 'metadata'::text ->> 'category'::text AS category,
    (r.value -> 'extra'::text) -> 'metadata'::text ->> 'confidence'::text AS confidence,
    (r.value -> 'extra'::text) -> 'metadata'::text -> 'vulnerability_class'::text AS vulnerability_class,
    (r.value -> 'extra'::text) -> 'metadata'::text -> 'cwe'::text AS cwe,
    semgrep_repo_scans._mergestat_synced_at
   FROM semgrep_repo_scans,
    LATERAL jsonb_array_elements(semgrep_repo_scans.results -> 'results'::text) r(value);

COMMENT ON VIEW semgrep_repo_vulnerabilities IS 'List of semgrep repo vulnerabilities';