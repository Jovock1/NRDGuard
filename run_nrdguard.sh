#!/usr/bin/env bash
# Runs nrdguard.py with the correct interpreter (.venv, which has the
# `ollama` package that the system python3 lacks) and a lock so a slow
# run (LLM classification over ~600 batches, once per configured model)
# can't overlap with the next scheduled one.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$REPO_DIR/logs/cron"
LOCK_FILE="$REPO_DIR/.nrdguard.lock"

mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/$(date +%F_%H-%M-%S).log"

cd "$REPO_DIR"

exec {lock_fd}>"$LOCK_FILE"
if ! flock -n "$lock_fd"; then
    echo "$(date -Is) Another nrdguard run is already in progress; skipping." >>"$LOG_FILE"
    exit 0
fi

# nrdguard.py's push_to_github() commits and pushes whatever branch happens
# to be checked out -- it doesn't pin one itself. If a human leaves the repo
# on some other branch (e.g. mid investigation-report work) after this runs,
# every subsequent cron run silently commits the daily blocklist/log update
# there instead of GITHUB_BRANCH (default main), while the push step, run
# against a stale local `main`, no-ops without ever failing loudly. Pin the
# branch here so an unattended cron run can't be derailed by an interactive
# `git checkout` left over from earlier.
TARGET_BRANCH="$(grep -m1 '^GITHUB_BRANCH=' "$REPO_DIR/.env" 2>/dev/null | cut -d= -f2- | tr -d '\r[:space:]')"
TARGET_BRANCH="${TARGET_BRANCH:-main}"
CURRENT_BRANCH="$(git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD)"
if [ "$CURRENT_BRANCH" != "$TARGET_BRANCH" ]; then
    echo "$(date -Is) On branch '$CURRENT_BRANCH', not '$TARGET_BRANCH' (GITHUB_BRANCH); switching before running." >>"$LOG_FILE"
    git -C "$REPO_DIR" checkout "$TARGET_BRANCH" >>"$LOG_FILE" 2>&1
fi

"$REPO_DIR/.venv/bin/python3" "$REPO_DIR/nrdguard.py" "$@" >>"$LOG_FILE" 2>&1
