#!/usr/bin/env bash
# End-to-end check of the generic runtime: a hand-written .entities file becomes
# a working, validated HTTP API. Nothing here is entity-specific in the runtime --
# every rule exercised below is read off the model at request time.
#
# Requires a reachable PostgreSQL. Override with PGHOST/PGPORT/PGUSER.
set -uo pipefail

export PGHOST="${PGHOST:-127.0.0.1}"
export PGPORT="${PGPORT:-54329}"
export PGUSER="${PGUSER:-postgres}"
PORT="${PORT:-8137}"
DB="${DB:-gooi_smoke}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="$ROOT/examples/tasks.entities"
B="http://127.0.0.1:$PORT"
fails=0

check() { # name expected actual
  if [ "$2" = "$3" ]; then printf '  ok   %-44s %s\n' "$1" "$3"
  else
    printf '  FAIL %-44s expected %s, got %s\n' "$1" "$2" "$3"
    [ -s /tmp/gooi_smoke_body ] && printf '       body: %s\n' "$(head -c 300 /tmp/gooi_smoke_body)"
    fails=$((fails+1))
  fi
}
# Extracts a JSON field from the last response body, or empty on failure.
field() { python3 -c "
import json,sys
try: print(json.load(open('/tmp/gooi_smoke_body'))['$1'])
except Exception: print('')
"; }
code() { curl -s -o /tmp/gooi_smoke_body -w '%{http_code}' "$@"; }
body() { cat /tmp/gooi_smoke_body; }

psql -tAc 'select 1' >/dev/null || { echo "no PostgreSQL at $PGHOST:$PGPORT"; exit 1; }

cargo build -q -p app-runtime || exit 1
cargo run -q -p app-runtime -- "$SPEC" --port "$PORT" --database "$DB" --reset >/tmp/gooi_smoke.log 2>&1 &
RUNTIME=$!
trap 'kill $RUNTIME 2>/dev/null; wait $RUNTIME 2>/dev/null' EXIT

for _ in $(seq 1 40); do
  curl -s -o /dev/null "$B/" && break
  sleep 0.5
done

echo "a hand-written .entities file, served:"
check "discovery"                200 "$(code "$B/")"
check "openapi document"         200 "$(code "$B/openapi.json")"
check "empty collection"         200 "$(code "$B/Task")"

# JSON bodies are assembled into variables first. Writing a brace-bearing
# literal inside a nested command substitution invites brace expansion, which
# silently splits the body on its commas and sends fragments.
post() { # entity json
  code -X POST "$B/$1" -H 'content-type: application/json' -d "$2"
}
patch() { # entity id json
  code -X PATCH "$B/$1/$2" -H 'content-type: application/json' -d "$3"
}

check "create team"              201 "$(post Team '{"name":"Platform"}')"
TEAM_ID="$(field id)"
check "team has a generated id"  32 "$(printf %s "$TEAM_ID" | tr -d - | wc -c | tr -d ' ')"

PERSON_BODY=$(printf '{"email":"ada@example.com","name":"Ada","teamId":"%s"}' "$TEAM_ID")
check "create person"            201 "$(post Person "$PERSON_BODY")"
PERSON_ID="$(field id)"

TASK_BODY=$(printf '{"title":"Ship it","assigneeId":"%s","teamId":"%s"}' "$PERSON_ID" "$TEAM_ID")
check "create task"              201 "$(post Task "$TASK_BODY")"
TASK_ID="$(field id)"
check "authored default: status" todo "$(field status)"
check "authored default: priority" 3 "$(field priority)"

echo "validation, derived from the model:"
check "unknown field"            400 "$(post Task '{"title":"x","bogus":1}')"
check "enum non-member"          400 "$(post Task '{"title":"x","status":"ship-it"}')"
check "wrong scalar type"        400 "$(post Task '{"title":123}')"
check "missing required"         400 "$(post Task '{"notes":"only notes"}')"
check "null on required"         400 "$(patch Task "$TASK_ID" '{"title":null}')"
check "identity is immutable"    400 "$(patch Task "$TASK_ID" '{"id":"x"}')"
check "malformed path id"        400 "$(code "$B/Task/not-a-uuid")"
check "invalid JSON"             400 "$(post Team '{oops')"

echo "constraints enforced by the store:"
check "duplicate unique"         409 "$(post Team '{"name":"Platform"}')"
check "delete referenced row"    409 "$(code -X DELETE "$B/Team/$TEAM_ID")"

echo "lifecycle:"
check "read one"                 200 "$(code "$B/Task/$TASK_ID")"
check "update"                   200 "$(patch Task "$TASK_ID" '{"status":"doing"}')"
code "$B/Task/$TASK_ID" >/dev/null
check "updated value persisted"  doing "$(field status)"
check "unknown entity"           404 "$(code "$B/Widget")"
check "unknown id"               404 "$(code "$B/Task/00000000-0000-0000-0000-000000000000")"
check "method not allowed"       405 "$(code -X PUT "$B/Task")"
check "delete"                   204 "$(code -X DELETE "$B/Task/$TASK_ID")"
check "gone after delete"        404 "$(code "$B/Task/$TASK_ID")"

echo
if [ "$fails" -ne 0 ]; then echo "SMOKE FAILED: $fails check(s)"; exit 1; fi
echo "SMOKE CLEAN: a text file became a validated API"
