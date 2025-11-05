#!/usr/bin/env bash
# 🧰 dead-domains-checker.sh — AdGuard-compatible batch checker
# Works on Linux and macOS runners (GNU/BSD userspace). Parallel curl enabled.
# --------------------------------------------------------------

API="https://urlfilter.adtidy.org/v2/checkDomains"
CHUNK_SIZE=500
BATCH_DIR="chunks"
OUT_DIR="responses"
OUTPUT_DIR="output"
MERGED_JSON="$OUTPUT_DIR/responses_merged.json"
RETRY_LIST="retry.list"
ACTIVE_LIST="$OUTPUT_DIR/active.txt"
REGISTERED_LIST="$OUTPUT_DIR/registered.txt"
INACTIVE_LIST="$OUTPUT_DIR/inactive.txt"
DNS_ALIVE_LIST="$OUTPUT_DIR/dns_alive.txt"
DNS_DEAD_LIST="$OUTPUT_DIR/dns_dead.txt"

# parallel knobs (override in env if needed)
MAX_PARALLEL="${MAX_PARALLEL:-4}"     # 4–6 is the sweet spot on GH runners
BATCH_SLEEP="${BATCH_SLEEP:-2}"       # pause between batches (seconds)
UA="${UA:-AdCheckLite/0.3 (+github.com/quiniapiezoelectricity)}"

mkdir -p "$BATCH_DIR" "$OUT_DIR" "$OUTPUT_DIR"

echo "🧹 Cleaning up old temporary data..."
rm -f "$BATCH_DIR"/chunk_* "$OUT_DIR"/*.json "$OUTPUT_DIR"/*.txt "$RETRY_LIST" 2>/dev/null || true

# 🧩 Split input into chunks
INPUT_FILE="${1:-domains.txt}"
if [[ ! -f "$INPUT_FILE" ]]; then
  echo "❌ Input file not found: $INPUT_FILE"
  exit 1
fi

# Note: macOS BSD split may lack -d; on GH Ubuntu it's available.
split -l "$CHUNK_SIZE" -d -a 3 "$INPUT_FILE" "$BATCH_DIR/chunk_" || {
  echo "❌ split failed"; exit 1;
}
for f in "$BATCH_DIR"/chunk_*; do
  mv "$f" "$f.txt"
done

chunks_count=$(ls "$BATCH_DIR"/chunk_* 2>/dev/null | wc -l | tr -d ' ')
if [[ "$chunks_count" -eq 0 ]]; then
  echo "❌ No chunks were created — input file may be empty or split failed."
  exit 1
fi

ls "$BATCH_DIR"/chunk_* > all_chunks.list
echo "✅ Split input into $chunks_count chunks."

# 🧠 Helper: Fetch a single chunk
fetch_chunk() {
  local f="$1"
  local chunk_name out_file post_data http_ok

  chunk_name=$(basename "$f" .txt)
  out_file="$OUT_DIR/${chunk_name}.json"

  printf "🧩 Processing %-10s (%8d domains)\n" "$chunk_name" "$(wc -l < "$f")"

  # Prepare POST data (domain=a&domain=b&...)
  post_data=$(awk '{printf "domain=%s&", $0}' "$f" | sed 's/&$//')

  # Perform the API request directly to file (so we can check exit + size)
  if ! curl -sS --http1.1 --compressed --max-time 60 \
      -A "$UA" -X POST -d "$post_data" "$API" -o "$out_file"; then
    echo "⚠️  Failed HTTP for chunk $chunk_name — requeueing."
    echo "$f" >> "$RETRY_LIST"
    rm -f "$out_file"
    return 1
  fi

  # Sanity: non-empty JSON and valid parse
  if [[ ! -s "$out_file" ]] || ! jq empty "$out_file" >/dev/null 2>&1; then
    echo "⚠️  Invalid/empty JSON for chunk $chunk_name — requeueing."
    echo "$f" >> "$RETRY_LIST"
    rm -f "$out_file"
    return 1
  fi

  echo "✅ [$chunk_name] Done → saved to $out_file"
  rm -f "$f"  # delete processed chunk
  return 0
}

# 🌀 Process chunks loop (parallel batches)
pass=1
while true; do
  echo "🔁 Pass #$pass — scanning for unprocessed chunks..."
  shopt -s nullglob
  remaining_chunks=( "$BATCH_DIR"/chunk_* )
  shopt -u nullglob

  # also check if any JSON responses are missing
  for f in "${remaining_chunks[@]}"; do
    [[ -f "$f" ]] || continue
    chunk_name=$(basename "$f" .txt)
    out_file="$OUT_DIR/${chunk_name}.json"
    [[ -f "$out_file" ]] || echo "$f" >> "$RETRY_LIST"
  done

  if [[ ! -s "$RETRY_LIST" ]]; then
    echo "✅ All chunks processed successfully!"
    break
  fi

  echo "⚠️  Found $(wc -l < "$RETRY_LIST") unfinished chunks — retrying..."
  jobs=0
  while read -r f; do
    [[ -f "$f" ]] || continue
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

# 📦 Merge JSON responses
echo "📦 Merging all JSON responses..."
jq -s 'add' "$OUT_DIR"/*.json > "$MERGED_JSON"

# 🧩 Parse domain activity
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

# 🔍 DNS recheck for inactive domains
echo "🔍 Rechecking inactive domains via DNS..."
touch "$DNS_ALIVE_LIST" "$DNS_DEAD_LIST"

if [[ -s "$INACTIVE_LIST" ]]; then
  total=$(wc -l < "$INACTIVE_LIST" | tr -d ' ')
  echo "📡 Checking $total potentially dead domains..."
  echo "-----------------------------------------------------"

  alive_count=0
  dead_count=0
  counter=0

  while IFS= read -r domain; do
    [[ -z "$domain" ]] && continue
    ((counter++))
    domain=$(echo "$domain" | tr -d '[:space:]')

    if dig +time=2 +tries=1 +short @1.1.1.1 "$domain" >/dev/null 2>&1; then
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

dns_alive=$(wc -l < "$DNS_ALIVE_LIST" | tr -d ' ')
dns_dead=$(wc -l < "$DNS_DEAD_LIST" | tr -d ' ')
echo "-----------------------------------------------------"
echo "✅ DNS alive:   $dns_alive"
echo "💀 DNS dead:    $dns_dead"
echo "-----------------------------------------------------"

# 🧹 Cleanup (optional debug flag)
DEBUG="${DEBUG:-0}"
if [[ "$DEBUG" -eq 0 ]]; then
  echo "🧹 Cleaning up chunk and response files..."
  rm -rf "$BATCH_DIR" "$OUT_DIR"
fi

# 🧩 Merge all domains that are not dead
echo "📦 Combining verified active domains..."
VALIDATED_LIST="$OUTPUT_DIR/validated_domains.txt"
touch "$VALIDATED_LIST"

cat "$ACTIVE_LIST" "$REGISTERED_LIST" "$DNS_ALIVE_LIST" 2>/dev/null \
  | grep -v '^[[:space:]]*$' \
  | sort -u > "$VALIDATED_LIST"

validated_count=$(wc -l < "$VALIDATED_LIST" | tr -d ' ')
dead_count=$(wc -l < "$DNS_DEAD_LIST" | tr -d ' ')

echo "-----------------------------------------------------"
echo "🎯 Final domain summary"
echo "-----------------------------------------------------"
printf "✅ Total validated domains: %s\n" "$validated_count"
printf "💀 Total confirmed dead:    %s\n" "$dead_count"
echo "-----------------------------------------------------"

if [[ "$DEBUG" -eq 1 ]]; then
  echo "🔎 Preview of validated domains:"
  head -n 10 "$VALIDATED_LIST"
  echo "..."
fi

echo "✅ Merged validated domain list saved as: $VALIDATED_LIST"
echo "🎉 Done. Results saved in: $OUTPUT_DIR/"
