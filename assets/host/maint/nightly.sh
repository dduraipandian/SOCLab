#!/bin/bash
# Nightly password-expiry audit (made-up maintenance job, scenario S6).
# Runs as svc-maint from cron on build-01 and reads /etc/shadow via group "shadow".
awk -F: '{print $1, $5}' /etc/shadow > /tmp/pw-expiry-report.txt
