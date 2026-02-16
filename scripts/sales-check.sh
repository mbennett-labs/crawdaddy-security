#!/bin/bash
# CrawDaddyDev Gumroad Sales Monitor
# Runs daily at 9:00 AM EST

openclaw message send --channel telegram --target 6712910089 --message "Check Gumroad for any new sales of the Post-Quantum Security Playbook in the last 24 hours. Report: number of sales, total revenue, and buyer emails (if available) so I can send follow-up outreach. Send the summary to me." --json
