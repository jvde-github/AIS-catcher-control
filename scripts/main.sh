#!/bin/bash
# start.sh - Main Docker entrypoint script

PID_FILE="/tmp/ais_catcher.pid"
COMMAND_FILE="/tmp/command"
CONFIG_DIR="/config"
TARGET_DIR="/etc/AIS-catcher"

mkdir -p "$TARGET_DIR"

if [ ! -f "$TARGET_DIR/control.json" ] && [ ! -f "$TARGET_DIR/config.json" ] && [ ! -f "$TARGET_DIR/control.cmd" ]; then
    echo "Configuration files not found in $TARGET_DIR. Copying from $CONFIG_DIR."
    cp "$CONFIG_DIR/control.json" "$TARGET_DIR/control.json"
    cp "$CONFIG_DIR/config.json" "$TARGET_DIR/config.json"
    cp "$CONFIG_DIR/config.cmd" "$TARGET_DIR/config.cmd"

    chmod 644 "$TARGET_DIR/control.json" "$TARGET_DIR/config.json" "$TARGET_DIR/config.cmd"
    chown root:root "$TARGET_DIR/control.json" "$TARGET_DIR/config.json" "$TARGET_DIR/control.cmd"
else
    echo "One or more configuration files already exist. Skipping copy."
fi

chmod 755 "$TARGET_DIR"
chown -R root:root "$TARGET_DIR"

start_ais_catcher() {
    if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo "AIS-catcher is already running"
        return
    fi

    echo "Starting AIS-catcher..."
    /usr/local/bin/AIS-catcher -C /etc/AIS-catcher/config.json -q -G /etc/AIS-catcher/log.txt "$@" &
    echo $! > "$PID_FILE"
}

stop_ais_catcher() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "Stopping AIS-catcher..."
            kill "$PID"
            rm "$PID_FILE"
        fi
    fi
}

restart_ais_catcher() {
    stop_ais_catcher
    sleep 1
    start_ais_catcher "$@"
}

# Start AIS-catcher initially
start_ais_catcher "$@"

# Start AIS-catcher-control
echo "Starting AIS-catcher-control..."
/usr/local/bin/AIS-catcher-control &
AIS_CONTROL_PID=$!

# Trap SIGTERM and SIGINT to clean up
trap "stop_ais_catcher; kill $AIS_CONTROL_PID 2>/dev/null; exit 0" SIGTERM SIGINT

# Monitor command file for control commands
while true; do
    if [ -f "$COMMAND_FILE" ]; then
        COMMAND=$(cat "$COMMAND_FILE")
        rm "$COMMAND_FILE"

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
        esac
    fi

    # Check if AIS-catcher-control is still running
    if ! kill -0 $AIS_CONTROL_PID 2>/dev/null; then
        echo "AIS-catcher-control has exited. Stopping container..."
        stop_ais_catcher
        exit 1
    fi

    # Make sleep interruptible
    sleep 1 &
    wait $!
done
