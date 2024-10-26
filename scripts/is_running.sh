#!/bin/bash
# is_running.sh - Checks if AIS-catcher is running
if pgrep -f "^/usr/local/bin/AIS-catcher " > /dev/null; then
    echo "AIS-catcher is running."
    exit 0
else
    echo "AIS-catcher is not running."
    exit 1
fi
