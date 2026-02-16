#!/bin/bash
# CrawDaddyDev Daily Content Generator
# Runs via cron at 7:00 AM EST (12:00 UTC)

PILLARS=(
  "post-quantum cryptography threats to healthcare"
  "HIPAA compliance and quantum computing risk"
  "blockchain security and DeFi vulnerabilities"
  "NIST post-quantum standards update"
  "healthcare data breach trends and prevention"
  "quantum-safe encryption migration strategies"
  "cryptographic agility for healthcare organizations"
)

DAY_INDEX=$(( $(date +%j) % ${#PILLARS[@]} ))
TOPIC="${PILLARS[$DAY_INDEX]}"

openclaw message send --channel telegram --target 6712910089 --message "Generate a LinkedIn post about: $TOPIC. Keep it under 1300 characters. Include a hook in the first line, one key insight, and a call-to-action mentioning Quantum Shield Labs. Make it professional but accessible. Max 3 hashtags at the end. Send it to me for approval before posting." --json
