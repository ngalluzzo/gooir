#!/usr/bin/env bash
# Store round trip: waist -> DDL -> a real PostgreSQL -> catalog -> waist.
#
# PostgreSQL is an independent implementation in the middle, so a symmetric
# mistake shared by this project's own lifter and lowerer cannot survive the
# trip -- unlike the pure round-trip law, which such a mistake passes.
#
# Requires a reachable PostgreSQL. Override with PGHOST/PGPORT/PGUSER.
set -euo pipefail

HOST="${PGHOST:-127.0.0.1}"
PORT="${PGPORT:-54329}"
USER="${PGUSER:-postgres}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
APPS=(umami-software_umami lukevella_rallly ghostfolio_ghostfolio documenso_documenso)

psql -h "$HOST" -p "$PORT" -U "$USER" -tAc 'select 1' >/dev/null

echo "waist -> DDL -> PostgreSQL -> catalog -> waist"
echo
status=0
for app in "${APPS[@]}"; do
  db="rt_$(echo "$app" | tr '.-' '__' | tr 'A-Z' 'a-z')"
  cargo run -q --bin ddl-round-trip -- emit "$app" > "$WORK/$app.sql" 2>/dev/null

  psql -h "$HOST" -p "$PORT" -U "$USER" -q -c "drop database if exists $db;" >/dev/null
  psql -h "$HOST" -p "$PORT" -U "$USER" -q -c "create database $db;" >/dev/null
  if ! psql -h "$HOST" -p "$PORT" -U "$USER" -d "$db" -q -v ON_ERROR_STOP=1 \
       -f "$WORK/$app.sql" >/dev/null 2>"$WORK/$app.err"; then
    echo "REJECTED $app"; sed 's/^/    /' "$WORK/$app.err" | head -5; status=1; continue
  fi

  psql -h "$HOST" -p "$PORT" -U "$USER" -d "$db" -tA \
       -f "$ROOT/scripts/introspect-postgres.sql" > "$WORK/$app.catalog.json"
  out="$(cargo run -q --bin ddl-round-trip -- compare "$app" "$WORK/$app.catalog.json" 2>/dev/null)"
  echo "$out"
  # any reported divergence line is indented; treat as failure
  if echo "$out" | grep -q '^    '; then status=1; fi
done

rm -rf "$WORK"
if [ "$status" -ne 0 ]; then
  echo; echo "STORE ROUND TRIP FAILED"; exit 1
fi
echo; echo "STORE ROUND TRIP CLEAN"
