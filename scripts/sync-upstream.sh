#!/usr/bin/env bash
# sync-upstream.sh — Apply new commits from upstream (itsliaaa/baileys) onto this fork.
# Conflicts are auto-resolved by keeping YOUR fork's version (--theirs = cherry-pick source).
# Usage:
#   bash scripts/sync-upstream.sh              # dry-run: show what would be applied
#   bash scripts/sync-upstream.sh --apply      # actually apply commits
#   bash scripts/sync-upstream.sh --apply --from=<commit-sha>  # start from specific commit

set -euo pipefail

UPSTREAM_REMOTE="upstream"
UPSTREAM_URL="https://github.com/itsliaaa/baileys.git"
UPSTREAM_BRANCH="main"
LOCAL_BRANCH="main"
LOG_FILE="scripts/sync-upstream.log"

APPLY=false
FROM_COMMIT=""

for arg in "$@"; do
    case "$arg" in
        --apply) APPLY=true ;;
        --from=*) FROM_COMMIT="${arg#--from=}" ;;
    esac
done

# ── Color helpers ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[sync]${NC} $*"; }
ok()   { echo -e "${GREEN}[ok]${NC}   $*"; }
warn() { echo -e "${YELLOW}[skip]${NC} $*"; }
err()  { echo -e "${RED}[err]${NC}  $*"; }

# ── Sanity checks ──────────────────────────────────────────────────────────────
if ! git rev-parse --is-inside-work-tree &>/dev/null; then
    err "Not inside a git repo. Run from repo root."; exit 1
fi

CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "$LOCAL_BRANCH" ]; then
    err "On branch '$CURRENT_BRANCH', expected '$LOCAL_BRANCH'. Switch branches first."; exit 1
fi

DIRTY=$(git status --porcelain -uno | grep -v "^??" || true)
if [ -n "$DIRTY" ]; then
    err "Working tree dirty (tracked files modified). Commit or stash your changes first."
    echo "$DIRTY"
    exit 1
fi

# ── Register upstream remote if missing ───────────────────────────────────────
if ! git remote get-url "$UPSTREAM_REMOTE" &>/dev/null; then
    log "Adding remote '$UPSTREAM_REMOTE' → $UPSTREAM_URL"
    git remote add "$UPSTREAM_REMOTE" "$UPSTREAM_URL"
fi

# ── Fetch upstream ────────────────────────────────────────────────────────────
log "Fetching $UPSTREAM_REMOTE/$UPSTREAM_BRANCH ..."
git fetch "$UPSTREAM_REMOTE" "$UPSTREAM_BRANCH" --quiet

UPSTREAM_REF="$UPSTREAM_REMOTE/$UPSTREAM_BRANCH"

# ── Find the common ancestor ──────────────────────────────────────────────────
MERGE_BASE=$(git merge-base HEAD "$UPSTREAM_REF" 2>/dev/null || true)
if [ -z "$MERGE_BASE" ]; then
    err "No common ancestor between HEAD and $UPSTREAM_REF. Histories may be unrelated."; exit 1
fi

# ── Build list of new upstream commits ────────────────────────────────────────
if [ -n "$FROM_COMMIT" ]; then
    log "Collecting commits from $FROM_COMMIT to $UPSTREAM_REF ..."
    COMMITS=$(git log --reverse --pretty=format:"%H %s" "${FROM_COMMIT}..${UPSTREAM_REF}" 2>/dev/null || true)
else
    log "Collecting commits from merge-base ($MERGE_BASE) to $UPSTREAM_REF ..."
    COMMITS=$(git log --reverse --pretty=format:"%H %s" "${MERGE_BASE}..${UPSTREAM_REF}" 2>/dev/null || true)
fi

if [ -z "$COMMITS" ]; then
    ok "Already up to date with upstream. Nothing to apply."; exit 0
fi

TOTAL=$(echo "$COMMITS" | wc -l | tr -d ' ')
log "Found $TOTAL new upstream commit(s)."
echo ""

if [ "$APPLY" = false ]; then
    echo -e "${YELLOW}─── DRY RUN — pass --apply to actually sync ───${NC}"
    echo ""
    while IFS=' ' read -r sha rest; do
        MSG=$(git log --format="%s" -1 "$sha")
        AUTHOR=$(git log --format="%an" -1 "$sha")
        DATE=$(git log --format="%cd" --date=short -1 "$sha")
        echo -e "  ${CYAN}$sha${NC}  ${GREEN}$DATE${NC}  $AUTHOR"
        echo -e "      $MSG"
    done <<< "$COMMITS"
    echo ""
    echo -e "${YELLOW}Run with --apply to sync these commits.${NC}"
    exit 0
fi

# ── Apply commits one by one ──────────────────────────────────────────────────
mkdir -p scripts
echo "# sync-upstream log — $(date)" >> "$LOG_FILE"
echo "upstream: $UPSTREAM_URL" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

APPLIED=0; SKIPPED=0; ERRORED=0

while IFS=' ' read -r sha rest; do
    MSG=$(git log --format="%s" -1 "$sha")
    SHORT="${sha:0:10}"

    # Check if this commit (by its tree diff) is already applied
    # Using git log with --grep on commit message as heuristic
    if git log --format="%s" HEAD | grep -qF "$MSG"; then
        warn "$SHORT already in fork (same message): $MSG"
        echo "SKIP  $SHORT  $MSG" >> "$LOG_FILE"
        (( SKIPPED++ )) || true
        continue
    fi

    log "Applying $SHORT: $MSG"

    # cherry-pick with merge strategy: on conflict, keep ours (fork version)
    # --no-commit so we can inspect; then commit ourselves with original message
    if git cherry-pick --strategy=recursive -X theirs --no-commit "$sha" 2>/tmp/cp_err; then
        # Check if anything was actually staged
        if git diff --cached --quiet; then
            warn "$SHORT: no changes after applying (already identical)"
            git cherry-pick --abort 2>/dev/null || true
            echo "NOOP  $SHORT  $MSG" >> "$LOG_FILE"
            (( SKIPPED++ )) || true
        else
            # Commit with original message + upstream tag
            ORIG_MSG=$(git log --format="%B" -1 "$sha")
            git commit --no-edit -m "$ORIG_MSG

upstream-commit: $sha" --quiet
            ok "$SHORT applied: $MSG"
            echo "APPLY $SHORT  $MSG" >> "$LOG_FILE"
            (( APPLIED++ )) || true
        fi
    else
        CP_ERR=$(cat /tmp/cp_err)
        warn "$SHORT CONFLICT — keeping fork version: $MSG"
        warn "  error: $CP_ERR"
        # Abort cherry-pick and continue
        git cherry-pick --abort 2>/dev/null || true
        echo "SKIP  $SHORT  CONFLICT  $MSG" >> "$LOG_FILE"
        echo "      error: $CP_ERR" >> "$LOG_FILE"
        (( SKIPPED++ )) || true
    fi
done <<< "$COMMITS"

echo ""
echo "─────────────────────────────────────────"
ok "Done. Applied: $APPLIED | Skipped: $SKIPPED | Errors: $ERRORED"
log "Log saved to $LOG_FILE"
