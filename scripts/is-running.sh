#!/bin/bash
# is_running.sh - Checks if AIS-catcher is running
if pgrep -f "^/usr/bin/AIS-catcher " > /dev/null; then
    exit 0
else
    exit 1
fi
