#!/usr/bin/env bash
# Runs every migration and every pgTAP test against a throwaway database on a
# plain local Postgres (16+) with pgTAP installed. For machines where the
# Supabase Docker stack is unavailable. CI uses `supabase test db` instead.
#
#   scripts/db/test-local.sh            # migrate + run all tests
#   scripts/db/test-local.sh --no-tests # migrate only (leaves the DB in place)
#   scripts/db/test-local.sh --seed     # migrate + supabase/seed.sql + tests
#   RECREPORTS_TEST_DB=mydb scripts/db/test-local.sh   # use another database name
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DB="${RECREPORTS_TEST_DB:-recreports_test}"

if [ "$(id -u)" = "0" ]; then
  exec su postgres -c "RECREPORTS_TEST_DB='$DB' bash '$ROOT/scripts/db/test-local.sh' $*"
fi

RUN_TESTS=1; SEED=0
for arg in "$@"; do
  case "$arg" in
    --no-tests) RUN_TESTS=0 ;;
    --seed) SEED=1 ;;
  esac
done

PSQL=(psql -X -q -v ON_ERROR_STOP=1)

"${PSQL[@]}" -d postgres -c "drop database if exists $DB with (force)" -c "create database $DB"
"${PSQL[@]}" -d "$DB" -f "$ROOT/scripts/db/local-supabase-shim.sql"
"${PSQL[@]}" -d "$DB" -c "alter database $DB set search_path = \"\$user\", public, extensions"

shopt -s nullglob
for f in "$ROOT"/supabase/migrations/*.sql; do
  echo "migrate: $(basename "$f")"
  "${PSQL[@]}" -d "$DB" -1 -f "$f"
done

if [ "$SEED" = "1" ] && [ -f "$ROOT/supabase/seed.sql" ]; then
  echo "seed: supabase/seed.sql"
  "${PSQL[@]}" -d "$DB" -1 -f "$ROOT/supabase/seed.sql"
fi

if [ "$RUN_TESTS" = "1" ]; then
  "${PSQL[@]}" -d "$DB" -c "create extension if not exists pgtap with schema extensions"
  tests=("$ROOT"/supabase/tests/*.sql "$ROOT"/supabase/tests/**/*.sql)
  if [ "${#tests[@]}" -eq 0 ]; then echo "no pgTAP tests found"; exit 0; fi
  pg_prove -d "$DB" --ext .sql "${tests[@]}"
fi
