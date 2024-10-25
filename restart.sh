#!/bin/bash

# restart.sh - Signals the main script to restart AIS-catcher.

# Create the restart flag
touch /tmp/restart_flag

# Kill AIS-catcher process to trigger restart
pkill -f "/usr/local/bin/AIS-catcher"
