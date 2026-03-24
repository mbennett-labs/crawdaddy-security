#!/bin/bash
# QSL Swarm Alarm — fires on CRITICAL/WARNING events
# Usage: alarm.sh CRITICAL "Seller rejected job 1234"
# Usage: alarm.sh WARNING "Conway credits below $2"

SEVERITY="${1:-WARNING}"
MESSAGE="${2:-No message provided}"
TIMESTAMP=$(date -u '+%Y-%m-%d %H:%M UTC')

# Credentials (same as watchdog scripts)
BOT_TOKEN="REDACTED_TOKEN_1"
CHAT_ID="REDACTED_CHAT_ID"
EMAIL_TO="michael@quantumshieldlabs.dev"

EMOJI="⚠️"
[ "$SEVERITY" = "CRITICAL" ] && EMOJI="🚨"

FULL_MSG="$EMOJI QSL SWARM $SEVERITY
$MESSAGE
Time: $TIMESTAMP
Dashboard: qsl-dashboard.vercel.app"

# Channel 1: Telegram
if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
  curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
    -d chat_id="$CHAT_ID" \
    -d text="$FULL_MSG" > /dev/null 2>&1 &
fi

# Channel 2: Email via sendmail
if command -v sendmail &>/dev/null; then
  echo -e "Subject: QSL $SEVERITY ALERT\nTo: $EMAIL_TO\n\n$FULL_MSG" | \
    sendmail "$EMAIL_TO" 2>/dev/null &
fi

# Channel 3: Twilio SMS (TODO — no credentials found)
# if [ -n "$TWILIO_SID" ] && [ -n "$TWILIO_AUTH" ] && [ -n "$TWILIO_FROM" ] && [ -n "$TWILIO_TO" ]; then
#   curl -s -X POST "https://api.twilio.com/2010-04-01/Accounts/$TWILIO_SID/Messages.json" \
#     -u "$TWILIO_SID:$TWILIO_AUTH" \
#     -d "From=$TWILIO_FROM" -d "To=$TWILIO_TO" -d "Body=$FULL_MSG" > /dev/null 2>&1 &
# fi

# Wait for background sends
wait

# Log every alarm
mkdir -p /home/ubuntu/crawdaddy-security/logs
echo "[$TIMESTAMP] $SEVERITY: $MESSAGE" >> /home/ubuntu/crawdaddy-security/logs/alarms.log
