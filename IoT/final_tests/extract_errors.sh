#!/usr/bin/env bash
#
# extract_errors.sh - Extract errors from NDSL server logs (UTF-16LE encoded)
#
# Usage: ./extract_errors.sh [output_dir]
#   output_dir: directory to write error files (default: ./errors)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-$SCRIPT_DIR/errors}"

mkdir -p "$OUTPUT_DIR"

# Convert UTF-16LE to UTF-8 and strip CR
decode() {
    iconv -f UTF-16LE -t UTF-8 "$1" | tr -d '\r'
}

echo "=== Extracting errors from server logs ==="
echo "Output directory: $OUTPUT_DIR"
echo

# --- 1. logs_ca.txt (CA server - Go app via systemd) ---
# Errors contain "error", "fatal", "panic", or "fail" in the message
INPUT="$SCRIPT_DIR/logs_ca.txt"
OUTPUT="$OUTPUT_DIR/errors_ca.txt"
if [[ -f "$INPUT" ]]; then
    decode "$INPUT" | grep -iE '(error|fatal|panic|fail|refused|timeout|cannot)' > "$OUTPUT" || true
    COUNT=$(wc -l < "$OUTPUT" | tr -d ' ')
    echo "logs_ca.txt:              $COUNT error(s) -> $OUTPUT"
else
    echo "logs_ca.txt:              MISSING"
fi

# --- 2. logs_ra.txt (RA server - Django/Gunicorn via systemd) ---
# Gunicorn logs use [ERROR], [CRITICAL]; Django uses ERROR/Traceback
INPUT="$SCRIPT_DIR/logs_ra.txt"
OUTPUT="$OUTPUT_DIR/errors_ra.txt"
if [[ -f "$INPUT" ]]; then
    decode "$INPUT" | grep -iE '(\[ERROR\]|\[CRITICAL\]|Traceback|Exception|error|WORKER TIMEOUT|WORKER EXIT)' > "$OUTPUT" || true
    COUNT=$(wc -l < "$OUTPUT" | tr -d ' ')
    echo "logs_ra.txt:              $COUNT error(s) -> $OUTPUT"
else
    echo "logs_ra.txt:              MISSING"
fi

# --- 3. logs_data.txt (Data server - Go app via systemd) ---
# Go http server logs errors inline (e.g., "TLS handshake error", "http: error")
INPUT="$SCRIPT_DIR/logs_data.txt"
OUTPUT="$OUTPUT_DIR/errors_data.txt"
if [[ -f "$INPUT" ]]; then
    decode "$INPUT" | grep -iE '(error|fatal|panic|fail|refused|timeout|cannot)' > "$OUTPUT" || true
    COUNT=$(wc -l < "$OUTPUT" | tr -d ' ')
    echo "logs_data.txt:            $COUNT error(s) -> $OUTPUT"
else
    echo "logs_data.txt:            MISSING"
fi

# --- 4. logs_ra_nginx.txt (nginx systemd journal) ---
# Systemd-level failures: "failed", "error", "abort", "dumped"
INPUT="$SCRIPT_DIR/logs_ra_nginx.txt"
OUTPUT="$OUTPUT_DIR/errors_ra_nginx.txt"
if [[ -f "$INPUT" ]]; then
    decode "$INPUT" | grep -iE '(fail|error|abort|dumped|emergency|alert|fatal)' > "$OUTPUT" || true
    COUNT=$(wc -l < "$OUTPUT" | tr -d ' ')
    echo "logs_ra_nginx.txt:        $COUNT error(s) -> $OUTPUT"
else
    echo "logs_ra_nginx.txt:        MISSING"
fi

# --- 5. logs_ra_nginx_error.txt (nginx error log) ---
# Nginx error levels: [emerg], [alert], [crit], [error], [warn]
# Exclude [notice] and [info] which are informational
INPUT="$SCRIPT_DIR/logs_ra_nginx_error.txt"
OUTPUT="$OUTPUT_DIR/errors_ra_nginx_error.txt"
if [[ -f "$INPUT" ]]; then
    decode "$INPUT" | grep -E '\[(emerg|alert|crit|error|warn)\]' > "$OUTPUT" || true
    COUNT=$(wc -l < "$OUTPUT" | tr -d ' ')
    echo "logs_ra_nginx_error.txt:  $COUNT error(s) -> $OUTPUT"
else
    echo "logs_ra_nginx_error.txt:  MISSING"
fi

# --- 6. logs_ra_nginx_access.txt (nginx access log) ---
# Extract requests with HTTP status 4xx, 5xx, or 0xx (upstream failures)
# Status code is the field after the closing quote of the request line
INPUT="$SCRIPT_DIR/logs_ra_nginx_access.txt"
OUTPUT="$OUTPUT_DIR/errors_ra_nginx_access.txt"
if [[ -f "$INPUT" ]]; then
    decode "$INPUT" | grep -E 'HTTP/1\.[01]" [^23]' > "$OUTPUT" || true
    COUNT=$(wc -l < "$OUTPUT" | tr -d ' ')
    echo "logs_ra_nginx_access.txt: $COUNT error(s) -> $OUTPUT"
else
    echo "logs_ra_nginx_access.txt: MISSING"
fi

echo
echo "=== Done ==="
