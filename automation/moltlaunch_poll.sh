#!/bin/bash
# CrawDaddy Moltlaunch Inbox Poller — every 5 min via cron

AGENT_ID="17484"
LOG_DIR="/home/ubuntu/crawdaddy-automation/logs"
LOG_FILE="${LOG_DIR}/moltlaunch-$(date +%Y-%m-%d).log"
mkdir -p "$LOG_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log "=== Moltlaunch Poll ==="

# Check inbox
INBOX=$(mltl inbox --agent "$AGENT_ID" --json 2>/dev/null || echo '{"error": true}')
if echo "$INBOX" | grep -q '"error"'; then
    log "ERROR: inbox check failed"
else
    TOTAL=$(echo "$INBOX" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total', 0))" 2>/dev/null || echo "0")
    log "Inbox: $TOTAL tasks"
    if [ "$TOTAL" -gt "0" ]; then
        log "NEW TASKS: $INBOX"
    fi
fi

# Check fees
FEES=$(mltl fees --json 2>/dev/null || echo '{}')
log "Fees: $FEES"

# Check earnings
EARNINGS=$(mltl earnings --json 2>/dev/null || echo '{}')
log "Earnings: $EARNINGS"

log "=== Poll Complete ==="
