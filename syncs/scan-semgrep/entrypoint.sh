#!/usr/bin/env sh

set -euox pipefail

# This script uses semgrep (https://github.com/semgrep/semgrep)
# to perform static code scans

psql $MERGESTAT_POSTGRES_URL -1 --quiet --file /syncer/schema.sql

semgrep scan --config /syncer/semgrep-rules . --metrics=off --json --output="_mergestat_semgrep_scan_results.json"

jq -rc '[env.MERGESTAT_REPO_ID, . | tostring] | @csv' _mergestat_semgrep_scan_results.json \
  | psql $MERGESTAT_POSTGRES_URL -1 --quiet \
      -c "\set ON_ERROR_STOP on" \
      -c "DELETE FROM public.semgrep_repo_scans WHERE repo_id = '$MERGESTAT_REPO_ID'" \
      -c "\copy public.semgrep_repo_scans (repo_id, results) FROM stdin (FORMAT csv)";
