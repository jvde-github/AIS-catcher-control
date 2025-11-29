#!/bin/bash

# Check if this is first run
if [ ! -f /var/lib/ais-catcher-installed ]; then
    echo "First run detected - installing AIS-catcher and AIS-catcher-control..."
    
    # Install AIS-catcher (systemd will work now since we're running)
    echo "Installing AIS-catcher..."
    bash -c "$(curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher/main/scripts/aiscatcher-install) _ -p"
    
    # Install AIS-catcher-control
    echo "Installing AIS-catcher-control..."
    bash -c "$(curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher-control/main/install_ais_catcher_control.sh)"
    
    # Mark as installed
    touch /var/lib/ais-catcher-installed
    
    echo "Installation complete - services will start with systemd"
else
    echo "AIS-catcher already installed - starting services..."
fi

# Start systemd
exec /lib/systemd/systemd
