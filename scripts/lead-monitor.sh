#!/bin/bash
# CrawDaddyDev Lead & Opportunity Monitor
# Runs via cron at 8:00 AM and 2:00 PM EST

openclaw message send --channel telegram --target 6712910089 --message "Run a lead scan. Search for: 1) Recent healthcare cybersecurity RFPs or contracts in DC/MD/VA area 2) LinkedIn posts about post-quantum cryptography or HIPAA compliance 3) New NIST announcements about PQC standards 4) Recent major healthcare data breaches (potential leads) 5) Government contract opportunities related to quantum-safe encryption. Summarize findings and send me the top 3 most actionable items with links. If nothing new, just send a brief update." --json
