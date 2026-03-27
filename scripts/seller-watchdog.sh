#!/bin/bash
# CrawDaddy Seller Watchdog - restarts seller if dead + alarm on failures

# QSL-7 Guard: exit immediately if seller.ts is already running (prevent duplicate spawn)
if pgrep -f "seller.ts" > /dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Seller already running (PID $(pgrep -f 'seller.ts' | head -1)) — skipping" >> /home/ubuntu/crawdaddy-security/logs/watchdog.log
    exit 0
fi

LOG="/home/ubuntu/crawdaddy-security/logs/watchdog.log"
ALARM="/home/ubuntu/crawdaddy-security/scripts/alarm.sh"
SELLER_LOG="/home/ubuntu/.openclaw/virtuals-acp/logs/seller.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
TODAY=$(date '+%Y-%m-%d')

if ! pgrep -f "seller.ts" > /dev/null; then
    echo "[$TIMESTAMP] Seller DOWN - restarting..." >> $LOG
    $ALARM CRITICAL "CrawDaddy seller is DOWN — jobs being rejected. PID missing."
    cd /home/ubuntu/.openclaw/virtuals-acp
    nohup npx tsx src/seller/runtime/seller.ts >> logs/seller.log 2>&1 &
    sleep 5
    if pgrep -f "seller.ts" > /dev/null; then
        echo "[$TIMESTAMP] Seller restarted OK" >> $LOG
        $ALARM WARNING "CrawDaddy seller restarted successfully"
    else
        echo "[$TIMESTAMP] Seller restart FAILED" >> $LOG
        $ALARM CRITICAL "CrawDaddy seller restart FAILED — manual intervention needed"
    fi
else
    echo "[$TIMESTAMP] Seller OK" >> $LOG
fi

# Check for job rejections today
if [ -f "$SELLER_LOG" ]; then
    REJECTIONS=$(grep "accept=false" "$SELLER_LOG" | grep "$TODAY" | wc -l)
    if [ "$REJECTIONS" -gt 0 ]; then
        LAST_REJECTION=$(grep "accept=false" "$SELLER_LOG" | tail -1)
        $ALARM CRITICAL "CrawDaddy REJECTING JOBS — $REJECTIONS today. Last: $LAST_REJECTION"
        echo "[$TIMESTAMP] ALERT: $REJECTIONS job rejections today" >> $LOG
    fi

    # Check for TransformErrors today
    TRANSFORM_ERRORS=$(grep "TransformError" "$SELLER_LOG" | grep "$TODAY" | wc -l)
    if [ "$TRANSFORM_ERRORS" -gt 0 ]; then
        $ALARM CRITICAL "CrawDaddy has $TRANSFORM_ERRORS TransformError(s) today — handler code broken"
        echo "[$TIMESTAMP] ALERT: $TRANSFORM_ERRORS TransformErrors today" >> $LOG
    fi
fi
