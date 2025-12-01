# AIS-catcher Control Dockerfile
#
# Simple approach: Uses official install scripts for both AIS-catcher and control app
# - AIS-catcher: https://raw.githubusercontent.com/jvde-github/AIS-catcher/main/scripts/aiscatcher-install
# - Control app: https://raw.githubusercontent.com/jvde-github/AIS-catcher-control/main/install_ais_catcher_control.sh
#
# Build: docker-compose build
# Run: docker-compose up -d
#
# -------------------
# Stage 1: Base image with systemd
# -------------------
FROM debian:bookworm-slim AS systemd-base

# Install systemd and dependencies
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    systemd \
    systemd-sysv \
    curl \
    ca-certificates \
    procps \
    sudo \
    bash && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Remove unnecessary systemd services for containers
RUN cd /lib/systemd/system/sysinit.target.wants/ && \
    ls | grep -v systemd-tmpfiles-setup | xargs rm -f && \
    rm -f /lib/systemd/system/multi-user.target.wants/* && \
    rm -f /etc/systemd/system/*.wants/* && \
    rm -f /lib/systemd/system/local-fs.target.wants/* && \
    rm -f /lib/systemd/system/sockets.target.wants/*udev* && \
    rm -f /lib/systemd/system/sockets.target.wants/*initctl* && \
    rm -f /lib/systemd/system/basic.target.wants/* && \
    rm -f /lib/systemd/system/anaconda.target.wants/*

# -------------------
# Stage 2: Final runtime image with installations
# -------------------
FROM systemd-base AS runtime

# Install dependencies for install scripts
RUN apt-get update && apt-get install -y unzip git jq iproute2

# Install AIS-catcher using the official install script (creates config.json and downloads webassets)
RUN bash -c "$(curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher/main/scripts/aiscatcher-install)" _ -p || true

# Install AIS-catcher-control using the official install script
RUN bash -c "$(curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher-control/main/install_ais_catcher_control.sh)" || true

# Enable both services
RUN systemctl enable ais-catcher.service || true
RUN systemctl enable ais-catcher-control.service || true

# Store initial config files in a separate location (volume mount will hide /etc/AIS-catcher)
RUN mkdir -p /opt/ais-catcher-defaults && \
    cp -r /etc/AIS-catcher/* /opt/ais-catcher-defaults/

# Create simple entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Copy defaults to volume if first run\n\
if [ ! -f /etc/AIS-catcher/config.json ]; then\n\
    cp -r /opt/ais-catcher-defaults/* /etc/AIS-catcher/\n\
fi\n\
\n\
# Start systemd (manages both services)\n\
exec /lib/systemd/systemd' > /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/entrypoint.sh

# Expose port for web interface
EXPOSE 8110

STOPSIGNAL SIGRTMIN+3
VOLUME ["/sys/fs/cgroup"]

CMD ["/usr/local/bin/entrypoint.sh"]
