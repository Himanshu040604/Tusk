#!/usr/bin/env bash
#
# sentinel-cron.sh — nightly refresh driver for IAM Policy Sentinel.
#
# Target platform: LINUX ONLY (per prod_imp.md Amendment 6 Theme H).
# Relies on flock(1) and /bin/bash, which ship with every Linux distro
# but are not guaranteed on macOS or Windows.  Do NOT port this to a
# PowerShell variant — the cadence tool of choice on non-Linux hosts
# is the GitHub Action under .github/workflows/sentinel-monitor.yml.
#
# Usage (from crontab):
#   0 6 * * *  /opt/sentinel/scripts/sentinel-cron.sh
#
# Env vars:
#   SENTINEL_LOG       — log file path        (default: /var/log/sentinel.log)
#   SENTINEL_HOME      — working directory    (default: /opt/sentinel)
#   SENTINEL_PYTHON    — uv/python invocation (default: uv run sentinel)
#   SENTINEL_LOCKFILE  — concurrency lock     (default: /var/lock/sentinel.lock)
#
# Concurrency: flock -n on LOCKFILE (fd 200); non-blocking — a second
# invocation while one is already running exits immediately with code 2.
# -----------------------------------------------------------------------------
set -euo pipefail

SENTINEL_LOG="${SENTINEL_LOG:-/var/log/sentinel.log}"
SENTINEL_HOME="${SENTINEL_HOME:-/opt/sentinel}"
SENTINEL_PYTHON="${SENTINEL_PYTHON:-uv run sentinel}"
SENTINEL_LOCKFILE="${SENTINEL_LOCKFILE:-/var/lock/sentinel.lock}"

# Trap-based exit logging — fires on ANY exit path (success, fail, signal).
trap 'rc=$?; printf "[sentinel-cron] exit=%d at %s\n" "$rc" "$(date -u +%FT%TZ)" >> "$SENTINEL_LOG"; exit $rc' EXIT

exec 200>"$SENTINEL_LOCKFILE"
if ! flock -n 200; then
    printf "[sentinel-cron] another run is in progress; aborting\n" \
        >> "$SENTINEL_LOG"
    exit 2
fi

cd "$SENTINEL_HOME"

{
    printf "[sentinel-cron] start %s\n" "$(date -u +%FT%TZ)"
    # --all walks every source; --live triggers the scrapers.  The CLI
    # already aggregates worst-exit-code so a non-zero from this call
    # propagates out through set -e.
    $SENTINEL_PYTHON refresh --all --live
    printf "[sentinel-cron] refresh complete\n"
} >> "$SENTINEL_LOG" 2>&1
