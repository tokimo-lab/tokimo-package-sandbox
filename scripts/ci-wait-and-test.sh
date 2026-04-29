#!/usr/bin/env bash
# Wait for tokimo-package-rootfs v1.6.0 release CI to finish, then fetch VM
# artifacts into <repo>/vm/ and run the Windows session tests.
#
# Usage:
#   bash scripts/ci-wait-and-test.sh                  # default: tag v1.6.0
#   bash scripts/ci-wait-and-test.sh v1.6.1
#
# Requirements: gh (authenticated), pwsh, cargo, Hyper-V on Windows.

set -euo pipefail

TAG="${1:-v1.6.0}"
SISTER_REPO="tokimo-lab/tokimo-package-rootfs"
POLL_SECS=20
TIMEOUT_SECS=2400  # 40 min

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

log() { printf '[ci-wait %s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { log "ERROR: $*"; exit 1; }

# ---------------------------------------------------------------------------
# 1) Wait for the workflow run targeting $TAG to finish.
# ---------------------------------------------------------------------------
log "Looking for workflow run for tag $TAG on $SISTER_REPO ..."

run_id=""
deadline=$(( $(date +%s) + TIMEOUT_SECS ))

while :; do
    # Pick the most recent run whose headBranch == TAG.
    run_id="$(
        gh run list --repo "$SISTER_REPO" --limit 30 \
            --json databaseId,headBranch,status,conclusion \
            --jq "[.[] | select(.headBranch == \"$TAG\")][0].databaseId" \
            2>/dev/null || true
    )"
    if [[ -n "$run_id" && "$run_id" != "null" ]]; then
        break
    fi
    [[ $(date +%s) -ge $deadline ]] && fail "no run for $TAG within timeout"
    log "  no run yet, sleeping ${POLL_SECS}s ..."
    sleep "$POLL_SECS"
done

log "Watching run $run_id ..."
while :; do
    read -r status conclusion < <(
        gh run view "$run_id" --repo "$SISTER_REPO" \
            --json status,conclusion \
            --jq '"\(.status) \(.conclusion // "")"'
    )
    log "  status=$status conclusion=$conclusion"
    if [[ "$status" == "completed" ]]; then
        [[ "$conclusion" == "success" ]] || fail "run $run_id finished with $conclusion"
        break
    fi
    [[ $(date +%s) -ge $deadline ]] && fail "run $run_id did not complete within timeout"
    sleep "$POLL_SECS"
done

log "CI succeeded."

# ---------------------------------------------------------------------------
# 2) Confirm the release exists and lists the expected assets.
# ---------------------------------------------------------------------------
log "Checking release $TAG assets ..."
gh release view "$TAG" --repo "$SISTER_REPO" \
    --json assets --jq '.assets[].name' | sort

needed=(
    "tokimo-amd64-boot.tar.zst"
    "tokimo-amd64-ext4-rootfs.vhdx.zip"
)
for n in "${needed[@]}"; do
    if ! gh release view "$TAG" --repo "$SISTER_REPO" \
        --json assets --jq '.assets[].name' | grep -qx "$n"; then
        fail "release $TAG missing asset: $n"
    fi
done

# ---------------------------------------------------------------------------
# 3) Fetch artifacts via pwsh script.
# ---------------------------------------------------------------------------
log "Running scripts/fetch-vm.ps1 -Tag $TAG -Force ..."
pwsh -NoProfile -ExecutionPolicy Bypass \
    -File "$repo_root/scripts/fetch-vm.ps1" \
    -Tag "$TAG" -Force

log "vm/ contents:"
ls -lh "$repo_root/vm/"

# ---------------------------------------------------------------------------
# 4) Run Windows session tests.
# ---------------------------------------------------------------------------
log "Running cargo test --test session ..."
cd "$repo_root"
cargo test --test session -- --test-threads=1 --nocapture
log "All done."
