#!/bin/bash
# start.sh - Final Docker entrypoint script with systemd-like auto-restart behavior

CONFIG_DIR="/config"
TARGET_DIR="/etc/AIS-catcher"
COMMAND_FILE="/tmp/command"
AUTO_RESTART_FILE="$TARGET_DIR/auto_restart_enabled"
MANUAL_STOP_FILE="$TARGET_DIR/manual_stop"

log() {
    echo "[WARNING] $*" >> /etc/AIS-catcher/log.txt
}

mkdir -p "$TARGET_DIR"

if [ ! -f "$AUTO_RESTART_FILE" ]; then
    echo "false" > "$AUTO_RESTART_FILE"  
fi

if [ ! -f "$MANUAL_STOP_FILE" ]; then
    echo "false" > "$MANUAL_STOP_FILE"  
    log "Manual stop flag set to false by default."
fi

if [ ! -f "$TARGET_DIR/control.json" ] && [ ! -f "$TARGET_DIR/config.json" ] && [ ! -f "$TARGET_DIR/config.cmd" ]; then
    log "Configuration files not found in $TARGET_DIR. Copying from $CONFIG_DIR."
    cp "$CONFIG_DIR/"*.json "$TARGET_DIR/" 2>/dev/null
    cp "$CONFIG_DIR/"*.cmd "$TARGET_DIR/" 2>/dev/null
    log "Configuration files copied."
else
    log "One or more configuration files already exist. Skipping copy."
fi

is_ais_catcher_running() {
    pgrep -f "/usr/bin/AIS-catcher " >/dev/null 2>&1
}

start_ais_catcher() {
    if is_ais_catcher_running; then
        log "AIS-catcher is already running."
        return
    fi

    log "Starting AIS-catcher..."
    /usr/bin/AIS-catcher -C /etc/AIS-catcher/config.json -q -v 60 -G /etc/AIS-catcher/log.txt  &

    sleep 1  # Allow some time to start
    if is_ais_catcher_running; then
        log "AIS-catcher started successfully."
        echo "false" > "$MANUAL_STOP_FILE"  # Reset manual_stop flag
        log "Manual stop flag set to false."
    else
        log "Failed to start AIS-catcher."
    fi
}

# Function to stop AIS-catcher
stop_ais_catcher() {
    if is_ais_catcher_running; then
        log "Stopping AIS-catcher..."
        pkill -f "/usr/bin/AIS-catcher "
        sleep 1  # Allow some time to stop
        if ! is_ais_catcher_running; then
            log "AIS-catcher stopped successfully."
            echo "true" > "$MANUAL_STOP_FILE"  # Indicate manual stop
            log "Manual stop flag set to true."
        else
            log "Failed to stop AIS-catcher."
        fi
    else
        log "AIS-catcher is not running."
    fi
}

# Function to restart AIS-catcher
restart_ais_catcher() {
    log "Restarting AIS-catcher..."
    stop_ais_catcher
    sleep 1
    start_ais_catcher "$@"
}

# Function to enable auto-restart
enable_auto_restart() {
    echo "true" > "$AUTO_RESTART_FILE"
    log "Auto-restart enabled."
}

# Function to disable auto-restart
disable_auto_restart() {
    echo "false" > "$AUTO_RESTART_FILE"
    log "Auto-restart disabled."
}

# Function to handle commands from COMMAND_FILE
handle_command() {
    local COMMAND="$1"
    case "$COMMAND" in
        "start")
            start_ais_catcher "$@"
            ;;
        "stop")
            stop_ais_catcher
            ;;
        "restart")
            restart_ais_catcher "$@"
            ;;
        "enable")
            enable_auto_restart
            ;;
        "disable")
            disable_auto_restart
            ;;
        *)
            log "Unknown command: $COMMAND"
            ;;
    esac
}

# Initialize: Start AIS-catcher and AIS-catcher-control
start_ais_catcher "$@"

log "Starting AIS-catcher-control..."
/usr/bin/AIS-catcher-control &
AIS_CONTROL_PID=$!
log "AIS-catcher-control started with PID $AIS_CONTROL_PID."

# Trap SIGTERM and SIGINT to clean up
cleanup() {
    log "Received termination signal. Shutting down..."
    stop_ais_catcher
    if [ -n "$AIS_CONTROL_PID" ] && kill -0 "$AIS_CONTROL_PID" 2>/dev/null; then
        kill "$AIS_CONTROL_PID"
        wait "$AIS_CONTROL_PID" 2>/dev/null
        log "AIS-catcher-control stopped."
    fi
    exit 0
}
trap cleanup SIGTERM SIGINT

# Main loop to monitor processes and handle commands
while true; do
    # Check for control commands
    if [ -f "$COMMAND_FILE" ]; then
        COMMAND=$(cat "$COMMAND_FILE")
        rm "$COMMAND_FILE"
        handle_command "$COMMAND"
    fi

    # Check if AIS-catcher has exited
    if ! is_ais_catcher_running; then
        # Check if AIS-catcher was stopped manually
        MANUAL_STOP_STATUS=$(cat "$MANUAL_STOP_FILE")

        AUTO_RESTART_STATUS=$(cat "$AUTO_RESTART_FILE")
        if [ "$AUTO_RESTART_STATUS" = "true" ] && [ "$MANUAL_STOP_STATUS" = "false" ]; then
            log "AIS-catcher has exited unexpectedly. Auto-restarting..."
            start_ais_catcher "$@"
        fi
    fi

    # Check if AIS-catcher-control is still running
    if [ -n "$AIS_CONTROL_PID" ] && ! kill -0 "$AIS_CONTROL_PID" 2>/dev/null; then
        log "AIS-catcher-control with PID $AIS_CONTROL_PID has exited. Stopping container..."
        stop_ais_catcher
        exit 1
    fi

    sleep 2
done
