#!/bin/bash

# Process path to look for
PROCESS_PATH="/usr/local/bin/AIS-catcher"

# Get the elapsed time for the specified process
ELAPSED_TIME=$(ps -eo etimes,cmd | awk -v path="$PROCESS_PATH" '$2 == path {print $1; exit}')

if [ -n "$ELAPSED_TIME" ]; then
    # Calculate days, hours, minutes, and seconds
    DAYS=$((ELAPSED_TIME / 86400))
    HOURS=$(( (ELAPSED_TIME % 86400) / 3600 ))
    MINUTES=$(( (ELAPSED_TIME % 3600) / 60 ))
    SECONDS=$((ELAPSED_TIME % 60))

    # Format the output based on non-zero values
    if [ $DAYS -gt 0 ]; then
        UPTIME="${DAYS}d ${HOURS}h ${MINUTES}m ${SECONDS}s"
    elif [ $HOURS -gt 0 ]; then
        UPTIME="${HOURS}h ${MINUTES}m ${SECONDS}s"
    elif [ $MINUTES -gt 0 ]; then
        UPTIME="${MINUTES}m ${SECONDS}s"
    else
        UPTIME="${SECONDS}s"
    fi

    # Print the formatted uptime
    echo "$UPTIME"
else
    # If the process is not running, output a message
    echo "Unknown"
fi

