#!/usr/bin/env bash
# telegram-send-doc.sh — Send a file as a Telegram document attachment
# Usage: bash telegram-send-doc.sh [--self-destruct] <file_path> <chat_id> [caption]

set -euo pipefail

[ -f /home/ubuntu/.env ] && source /home/ubuntu/.env

# Parse --self-destruct flag
SELF_DESTRUCT=false
if [ "${1:-}" = "--self-destruct" ]; then
    SELF_DESTRUCT=true
    shift
fi

FILE_PATH="${1:-}"
CHAT_ID="${2:-}"
CAPTION="${3:-}"

if [ -z "$FILE_PATH" ] || [ -z "$CHAT_ID" ]; then
    echo "Usage: telegram-send-doc.sh [--self-destruct] <file_path> <chat_id> [caption]"
    exit 1
fi

if [ ! -f "$FILE_PATH" ]; then
    echo "ERROR: File not found: $FILE_PATH"
    exit 1
fi

if [ -z "${TELEGRAM_BOT_TOKEN:-}" ]; then
    echo "ERROR: TELEGRAM_BOT_TOKEN not set in /home/ubuntu/.env"
    exit 1
fi

API_URL="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument"

if [ -n "$CAPTION" ]; then
    RESPONSE=$(curl -s -X POST "$API_URL" \
        -F "chat_id=${CHAT_ID}" \
        -F "document=@${FILE_PATH}" \
        -F "caption=${CAPTION}" \
        -F "parse_mode=Markdown" 2>&1)
else
    RESPONSE=$(curl -s -X POST "$API_URL" \
        -F "chat_id=${CHAT_ID}" \
        -F "document=@${FILE_PATH}" 2>&1)
fi

OK=$(echo "$RESPONSE" | jq -r '.ok // false' 2>/dev/null)

if [ "$OK" = "true" ]; then
    echo "SEND_DOC=success"

    if [ "$SELF_DESTRUCT" = "true" ]; then
        DOC_MSG_ID=$(echo "$RESPONSE" | jq -r '.result.message_id // empty' 2>/dev/null) || true

        if [ -n "$DOC_MSG_ID" ]; then
            # Send self-destruct warning
            WARNING_RESPONSE=$(curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
                -d "chat_id=${CHAT_ID}" \
                -d "text=⏳ This report will self-destruct in 1 hour. Download it now." \
                -d "reply_to_message_id=${DOC_MSG_ID}" 2>&1) || true
            WARNING_MSG_ID=$(echo "$WARNING_RESPONSE" | jq -r '.result.message_id // empty' 2>/dev/null) || true

            # Background process: delete both messages after 1 hour
            (
                sleep 3600
                curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/deleteMessage" \
                    -d "chat_id=${CHAT_ID}" -d "message_id=${DOC_MSG_ID}" > /dev/null 2>&1
                if [ -n "${WARNING_MSG_ID}" ]; then
                    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/deleteMessage" \
                        -d "chat_id=${CHAT_ID}" -d "message_id=${WARNING_MSG_ID}" > /dev/null 2>&1
                fi
            ) &
            disown
            echo "SELF_DESTRUCT=scheduled"
        fi
    fi
else
    ERROR=$(echo "$RESPONSE" | jq -r '.description // "unknown error"' 2>/dev/null)
    echo "SEND_DOC=failed"
    echo "SEND_DOC_ERROR=${ERROR}"
fi
