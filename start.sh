#!/bin/bash

# start.sh - Starts AIS-catcher and AIS-catcher-control and monitors them.

# File to signal a restart
RESTART_FLAG="/tmp/restart_flag"

# File to store start time
START_TIME_FILE="/tmp/container_start_time"

# Remove any existing restart flag
rm -f $RESTART_FLAG

# Record the start time
date +%s > $START_TIME_FILE

# Function to start AIS-catcher
start_ais_catcher() {
    echo "Starting AIS-catcher..."
    /usr/local/bin/AIS-catcher -r txt . -N 8100 -v -G /etc/AIS-catcher/log.txt "$@" &
    AIS_CATCHER_PID=$!
}

# Function to handle restart
restart_ais_catcher() {
    echo "Restarting AIS-catcher..."
    # Kill AIS-catcher if running
    if [ -n "$AIS_CATCHER_PID" ]; then
        kill $AIS_CATCHER_PID
        wait $AIS_CATCHER_PID 2>/dev/null
    fi
    # Start AIS-catcher again
    start_ais_catcher "$@"
}

# Start AIS-catcher-control
echo "Starting AIS-catcher-control..."
/usr/local/bin/AIS-catcher-control &
AIS_CATCHER_CONTROL_PID=$!

# Start AIS-catcher
start_ais_catcher "$@"

# Trap SIGTERM and SIGINT to terminate both processes
trap "echo 'Caught termination signal. Exiting...'; kill $AIS_CATCHER_PID $AIS_CATCHER_CONTROL_PID; exit 0" SIGTERM SIGINT

# Main loop
while true; do
    # Wait for any process to exit
    wait -n $AIS_CATCHER_PID $AIS_CATCHER_CONTROL_PID
    EXITED_PID=$!

    # Check if AIS-catcher-control has exited
    if ! kill -0 $AIS_CATCHER_CONTROL_PID 2>/dev/null; then
        echo "AIS-catcher-control has exited. Exiting container..."
        kill $AIS_CATCHER_PID 2>/dev/null
        exit 1
    fi

    # Check if AIS-catcher has exited
    if ! kill -0 $AIS_CATCHER_PID 2>/dev/null; then
        # Check for restart flag
        if [ -f $RESTART_FLAG ]; then
            # Remove the flag
            rm -f $RESTART_FLAG
            # Restart AIS-catcher
            restart_ais_catcher "$@"
        else
            echo "AIS-catcher has exited."
            # Do not exit the container; keep running
            AIS_CATCHER_PID=""
        fi
    fi
    # Sleep briefly to avoid tight loop
    sleep 1
done
