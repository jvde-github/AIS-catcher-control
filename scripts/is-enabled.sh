#!/bin/bash
# is_running.sh - Checks if AIS-catcher is running

CONFIG_DIR="/config"
TARGET_DIR="/etc/AIS-catcher"
COMMAND_FILE="/tmp/command"
AUTO_RESTART_FILE="$TARGET_DIR/auto_restart_enabled"
MANUAL_STOP_FILE="$TARGET_DIR/manual_stop"


AUTO_RESTART_STATUS=$(cat "$AUTO_RESTART_FILE")
        if [ "$AUTO_RESTART_STATUS" = "true" ]; then
echo "enabled"
        else
echo "disabled"
fi

