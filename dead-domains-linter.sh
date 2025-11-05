#!/usr/bin/env bash
# 🧰 dead-domains-checker.sh — AdGuard-compatible batch checker
# Portable on Linux/macOS (GNU/BSD coreutils). Requires: bash, curl, jq, dig.
#
# Usage:
#   ./dead-domains-checker.sh [OPTIONS] <input_file>
#
# Options:
#   -c, --chunk-size <N>      Domains per API request batch (default: 500)
#   -p, --max-parallel <N>    Concurrent curl requests (default: 4)
#   -s, --batch-sleep <SEC>   Sleep between parallel batches (default: 2)
#   -t, --max-time <SEC>      curl --max-time per request (default: 60)
#   -u, --user-agent <UA>     HTTP User-Agent (default shown below)
#   -A, --api <URL>           API endpoint (default: https://urlfilter.adtidy.org/v2/checkDomains)
#   -o, --output-dir <DIR>    Output directory (default: output)
#       --batch-dir <DIR>     Chunk dir (default: chunks)
#       --responses-dir <DIR> JSON responses dir (default: responses)
#       --dnscheck            Enable DNS recheck of “inactive” domains
#       --dns-server <IP>     Resolver for DNS recheck (default: 1.1.1.1)
#       --dns-timeout <SEC>   dig +time timeout (default: 2)
#       --dns-tries <N>       dig +tries attempts (default: 1)
#       --debug               Keep chunk/response files
#   -h, --help                Show help
#
# Example:
#   ./dead-domains-checker.sh -p 6 -t 75 --dnscheck domains.txt

set -o errexit
set -o nounset
set -o pipefail
set +e 
# Defaults
CHUNK_SIZE=500
MAX_PARALLEL=4
BATCH_SLEEP=2
MAX_TIME=60
UA="AdCheckLite/0.4 (+github.com/quiniapiezoelectricity)"
API="https://urlfilter.adtidy.org/v2/checkDomains"

BATCH_DIR="chunks"
OUT_DIR="responses"
OUTPUT_DIR="output"

DNSCHECK=0
DNS_SERVER="1.1.1.1"
DNS_TIMEOUT=2
DNS_TRIES=1
DEBUG=0

# Parse flags
if [[ $# -eq 0 ]]; then
  echo "Usage: $0 [OPTIONS] <input_file>" >&2
  exit 1
fi

INPUT_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--chunk-size)   CHUNK_SIZE="${2:?}"; shift 2 ;;
    -p|--max-parallel) MAX_PARALLEL="${2:?}"; shift 2 ;;
    -s|--batch-sleep)  BATCH_SLEEP="${2:?}"; shift 2 ;;
    -t|--max-time)     MAX_TIME="${2:?}"; shift 2 ;;
    -u|--user-agent)   UA="${2:?}"; shift 2 ;;
    -A|--api)          API="${2:?}"; shift 2 ;;
    -o|--output-dir)   OUTPUT_DIR="${2:?}"; shift 2 ;;
    --batch-dir)       BATCH_DIR="${2:?}"; shift 2 ;;
    --responses-dir)   OUT_DIR="${2:?}"; shift 2 ;;
    --dnscheck)        DNSCHECK=1; shift ;;
    --dns-server)      DNS_SERVER="${2:?}"; shift 2 ;;
    --dns-timeout)     DNS_TIMEOUT="${2:?}"; shift 2 ;;
    --dns-tries)       DNS_TRIES="${2:?}"; shift 2 ;;
    --debug)           DEBUG=1; shift ;;
    -h|--help)
      sed -n '1,80p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2; exit 2 ;;
    *)
      INPUT_FILE="$1"; shift ;;
  esac
done

if [[ -z "${INPUT_FILE}" ]]; then
  echo "❌ Input file is required." >&2
  exit 1
fi
if [[ ! -f "$INPUT_FILE" ]]; then
  echo "❌ Input file not found: $INPUT_FILE" >&2
  exit 1
fi

# Derived paths
MERGED_JSON="$OUTPUT_DIR/responses_merged.json"
RETRY_LIST="retry.list"
ACTIVE_LIST="$OUTPUT_DIR/active.txt"
REGISTERED_LIST="$OUTPUT_DIR/registered.txt"
INACTIVE_LIST="$OUTPUT_DIR/inactive.txt"
DNS_ALIVE_LIST="$OUTPUT_DIR/dns_alive.txt"
DNS_DEAD_LIST="$OUTPUT_DIR/dns_dead.txt"

# Tools check
for bin in curl jq dig split wc awk sed tr; do
  command -v "$bin" >/dev/null 2>&1 || { echo "❌ Missing dependency: $bin" >&2; exit 1; }
done

mkdir -p "$BATCH_DIR" "$OUT_DIR" "$OUTPUT_DIR"

echo "🧹 Cleaning up old temporary data..."
rm -f "$BATCH_DIR"/chunk_* "$OUT_DIR"/*.json "$OUTPUT_DIR"/*.txt "$RETRY_LIST" 2>/dev/null || true

echo "🧾 Config:"
echo "  Input:         $INPUT_FILE"
echo "  Chunk size:    $CHUNK_SIZE"
echo "  Parallel:      $MAX_PARALLEL"
echo "  Sleep:         ${BATCH_SLEEP}s"
echo "  Max time:      ${MAX_TIME}s"
echo "  UA:            $UA"
echo "  API:           $API"
echo "  DNS check:     $DNSCHECK (server $DNS_SERVER, time $DNS_TIMEOUT, tries $DNS_TRIES)"
echo "  Dirs:          chunks=$BATCH_DIR, responses=$OUT_DIR, output=$OUTPUT_DIR"
echo

# Split input (try GNU split, fallback to BSD)
if split -l "$CHUNK_SIZE" -d -a 3 "$INPUT_FILE" "$BATCH_DIR/chunk_" 2>/dev/null; then
  :
else
  # BSD split (no -d), suffix will be alphabetic but we don't rely on numeric
  split -l "$CHUNK_SIZE" -a 3 "$INPUT_FILE" "$BATCH_DIR/chunk_"
fi

# normalize to .txt
shopt -s nullglob
for f in "$BATCH_DIR"/chunk_*; do
  [[ -f "$f" ]] && mv "$f" "$f.txt"
done
shopt -u nullglob

chunks_count=$(ls "$BATCH_DIR"/chunk_* 2>/dev/null | wc -l | tr -d ' ')
if [[ "$chunks_count" -eq 0 ]]; then
  echo "❌ No chunks were created — input file may be empty or split failed." >&2
  exit 1
fi
ls "$BATCH_DIR"/chunk_* > all_chunks.list
echo "✅ Split input into $chunks_count chunks."

fetch_chunk() {
  local f="$1"
  local chunk_name out_file post_data
  chunk_name=$(basename "$f" .txt)
  out_file="$OUT_DIR/${chunk_name}.json"

  printf "🧩 Processing %-12s (%8d domains)\n" "$chunk_name" "$(wc -l < "$f")"

  # Build POST body: domain=a&domain=b&...
  post_data=$(awk '{printf "domain=%s&", $0}' "$f" | sed 's/&$//')

  if ! curl -sS --http1.1 --compressed --max-time "$MAX_TIME" \
        -A "$UA" -X POST -d "$post_data" "$API" -o "$out_file"; then
    echo "⚠️  HTTP failure for $chunk_name — will retry."
    rm -f "$out_file"
    return 1
  fi

  if [[ ! -s "$out_file" ]] || ! jq empty "$out_file" >/dev/null 2>&1; then
    echo "⚠️  Invalid/empty JSON for $chunk_name — will retry."
    rm -f "$out_file"
    return 1
  fi

  echo "✅ [$chunk_name] OK → $out_file"
  rm -f "$f"
  return 0
}

# 🌀 Process chunks loop (parallel batches)
pass=1

list_chunks() {
  # Populate remaining_chunks with current chunk files (or empty)
  local pattern="$BATCH_DIR/chunk_*"
  # Ensure the array is declared (avoids nounset error)
  remaining_chunks=()
  if compgen -G "$pattern" > /dev/null; then
    # nullglob behavior without changing shopt
    remaining_chunks=( "$BATCH_DIR"/chunk_* )
  else
    remaining_chunks=()  # explicit empty
  fi
}

while true; do
  echo "🔁 Pass #$pass — scanning for unprocessed chunks..."

  # 1) Build a fresh list of chunk files
  declare -a remaining_chunks=()
  list_chunks

  # 2) Build a retry list of chunks whose JSON is missing
  : > "$RETRY_LIST"
  if ((${#remaining_chunks[@]} > 0)); then
    for f in "${remaining_chunks[@]}"; do
      [[ -f "$f" ]] || continue
      chunk_name=$(basename "$f" .txt)
      out_file="$OUT_DIR/${chunk_name}.json"
      [[ -f "$out_file" ]] || echo "$f" >> "$RETRY_LIST"
    done
  fi

  # 3) If nothing to retry, we're done
  if [[ ! -s "$RETRY_LIST" ]]; then
    echo "✅ All chunks processed successfully!"
    break
  fi

  # 4) Retry unfinished chunks in parallel batches
  to_retry=$(wc -l < "$RETRY_LIST" | tr -d ' ')
  echo "⚠️  Retrying $to_retry unfinished chunk(s)..."

  jobs=0
  # Use the "${var[@]+"${var[@]}"}" idiom so nounset won't trip if empty
  while IFS= read -r f; do
    [[ -n "$f" && -f "$f" ]] || continue
    fetch_chunk "$f" &
    ((jobs++))
    if (( jobs >= MAX_PARALLEL )); then
      wait
      echo "⏸ Cooling down ${BATCH_SLEEP}s..."
      sleep "$BATCH_SLEEP"
      jobs=0
    fi
  done < "$RETRY_LIST"
  wait
  rm -f "$RETRY_LIST"

  ((pass++))
done
# 🌀 Process chunks loop (parallel batches)
pass=1

list_chunks() {
  # Populate remaining_chunks with current chunk files (or empty)
  local pattern="$BATCH_DIR/chunk_*"
  # Ensure the array is declared (avoids nounset error)
  remaining_chunks=()
  if compgen -G "$pattern" > /dev/null; then
    # nullglob behavior without changing shopt
    remaining_chunks=( "$BATCH_DIR"/chunk_* )
  else
    remaining_chunks=()  # explicit empty
  fi
}

while true; do
  echo "🔁 Pass #$pass — scanning for unprocessed chunks..."

  # 1) Build a fresh list of chunk files
  declare -a remaining_chunks=()
  list_chunks

  # 2) Build a retry list of chunks whose JSON is missing
  : > "$RETRY_LIST"
  if ((${#remaining_chunks[@]} > 0)); then
    for f in "${remaining_chunks[@]}"; do
      [[ -f "$f" ]] || continue
      chunk_name=$(basename "$f" .txt)
      out_file="$OUT_DIR/${chunk_name}.json"
      [[ -f "$out_file" ]] || echo "$f" >> "$RETRY_LIST"
    done
  fi

  # 3) If nothing to retry, we're done
  if [[ ! -s "$RETRY_LIST" ]]; then
    echo "✅ All chunks processed successfully!"
    break
  fi

  # 4) Retry unfinished chunks in parallel batches
  to_retry=$(wc -l < "$RETRY_LIST" | tr -d ' ')
  echo "⚠️  Retrying $to_retry unfinished chunk(s)..."

  jobs=0
  # Use the "${var[@]+"${var[@]}"}" idiom so nounset won't trip if empty
  while IFS= read -r f; do
    [[ -n "$f" && -f "$f" ]] || continue
    fetch_chunk "$f" &
    ((jobs++))
    if (( jobs >= MAX_PARALLEL )); then
      wait || true
      echo "⏸ Cooling down ${BATCH_SLEEP}s..."
      sleep "$BATCH_SLEEP"
      jobs=0
    fi
  done < "$RETRY_LIST"
  wait
  rm -f "$RETRY_LIST"

  ((pass++))
done


echo "📦 Merging all JSON responses..."
jq -s 'add' "$OUT_DIR"/*.json > "$MERGED_JSON"

echo "📊 Parsing domain activity status..."
jq -r '
  to_entries[] |
  if (.value.info.used_last_24_hours == true)
    then .key
  elif (.value.info.registered_domain_used_last_24_hours == true)
    then .key
  else empty end
' "$MERGED_JSON" > "$ACTIVE_LIST"

jq -r '
  to_entries[] |
  select(.value.info.registered_domain_used_last_24_hours == true and .value.info.used_last_24_hours == false) |
  .key
' "$MERGED_JSON" > "$REGISTERED_LIST"

jq -r '
  to_entries[] |
  select(.value.info.registered_domain_used_last_24_hours == false and .value.info.used_last_24_hours == false) |
  .key
' "$MERGED_JSON" > "$INACTIVE_LIST"

active_count=$(wc -l < "$ACTIVE_LIST" | tr -d ' ')
reg_count=$(wc -l < "$REGISTERED_LIST" | tr -d ' ')
inactive_count=$(wc -l < "$INACTIVE_LIST" | tr -d ' ')
echo "✅ Active:     $active_count"
echo "✅ Registered: $reg_count"
echo "✅ Inactive:   $inactive_count"

# Optional DNS recheck
if (( DNSCHECK )); then
  echo "🔍 Rechecking inactive domains via DNS (@${DNS_SERVER})..."
  : > "$DNS_ALIVE_LIST"
  : > "$DNS_DEAD_LIST"

  if [[ -s "$INACTIVE_LIST" ]]; then
    total=$(wc -l < "$INACTIVE_LIST" | tr -d ' ')
    echo "📡 Checking $total potentially dead domains..."
    echo "-----------------------------------------------------"

    alive_count=0
    dead_count=0
    counter=0

    # Sequential is the safest for shared runners/resolvers.
    while IFS= read -r domain; do
      [[ -z "$domain" ]] && continue
      ((counter++))
      domain=$(echo "$domain" | tr -d '[:space:]')

      if dig +short +time="$DNS_TIMEOUT" +tries="$DNS_TRIES" @"$DNS_SERVER" "$domain" >/dev/null 2>&1; then
        ((alive_count++))
        echo "[$counter/$total] ✅ DNS alive: $domain"
        echo "$domain" >> "$DNS_ALIVE_LIST"
      else
        ((dead_count++))
        echo "[$counter/$total] 💀 DNS dead:  $domain"
        echo "$domain" >> "$DNS_DEAD_LIST"
      fi
    done < "$INACTIVE_LIST"

    echo "-----------------------------------------------------"
    echo "✅ DNS alive:   $alive_count"
    echo "💀 DNS dead:    $dead_count"
    echo "-----------------------------------------------------"
  else
    echo "⚠️  No inactive domains to recheck via DNS."
  fi
else
  echo "⏭️  Skipping DNS recheck (use --dnscheck to enable)."
fi

dns_alive=$( [[ -f "$DNS_ALIVE_LIST" ]] && wc -l < "$DNS_ALIVE_LIST" | tr -d ' ' || echo 0 )
dns_dead=$(  [[ -f "$DNS_DEAD_LIST"  ]] && wc -l < "$DNS_DEAD_LIST"  | tr -d ' ' || echo 0 )
echo "-----------------------------------------------------"
echo "✅ DNS alive:   $dns_alive"
echo "💀 DNS dead:    $dns_dead"
echo "-----------------------------------------------------"

# Cleanup or keep artifacts
if (( DEBUG == 0 )); then
  echo "🧹 Cleaning up chunk and response files..."
  rm -rf "$BATCH_DIR" "$OUT_DIR"
else
  echo "🐞 Debug mode: keeping $BATCH_DIR and $OUT_DIR"
fi

# Final merge of “not dead” domains
echo "📦 Combining verified active domains..."
VALIDATED_LIST="$OUTPUT_DIR/validated_domains.txt"
: > "$VALIDATED_LIST"

# If DNSCHECK disabled, DNS_ALIVE_LIST may not exist — 2>/dev/null covers that
cat "$ACTIVE_LIST" "$REGISTERED_LIST" "$DNS_ALIVE_LIST" 2>/dev/null \
  | grep -v '^[[:space:]]*$' \
  | sort -u > "$VALIDATED_LIST"

validated_count=$(wc -l < "$VALIDATED_LIST" | tr -d ' ')
dead_count_final=$( [[ -f "$DNS_DEAD_LIST" ]] && wc -l < "$DNS_DEAD_LIST" | tr -d ' ' || echo 0 )

echo "-----------------------------------------------------"
echo "🎯 Final domain summary"
echo "-----------------------------------------------------"
printf "✅ Total validated domains: %s\n" "$validated_count"
printf "💀 Total confirmed dead:    %s\n" "$dead_count_final"
echo "-----------------------------------------------------"
echo "✅ Merged validated domain list saved as: $VALIDATED_LIST"
echo "🎉 Done. Results saved in: $OUTPUT_DIR/"