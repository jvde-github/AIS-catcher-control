#!/bin/bash

# uptime.sh - Returns the uptime of the container

START_TIME_FILE="/tmp/container_start_time"

if [ ! -f $START_TIME_FILE ]; then
    echo "Start time not recorded."
    exit 1
fi

START_TIME=$(cat $START_TIME_FILE)
CURRENT_TIME=$(date +%s)
UPTIME=$((CURRENT_TIME - START_TIME))

# Convert uptime to human-readable format
DAYS=$((UPTIME / 86400))
HOURS=$(( (UPTIME % 86400) / 3600 ))
MINUTES=$(( (UPTIME % 3600) / 60 ))
SECONDS=$(( UPTIME % 60 ))

echo "${DAYS}d ${HOURS}h ${MINUTES}m ${SECONDS}s"
