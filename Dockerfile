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
# Stage 2: Install AIS-catcher and control with systemd active
# -------------------
FROM systemd-base AS installer

# Pre-download install scripts to avoid runtime downloads
RUN curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher/main/scripts/aiscatcher-install -o /tmp/install-ais-catcher.sh && \
    curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher-control/main/install_ais_catcher_control.sh -o /tmp/install-ais-control.sh && \
    chmod +x /tmp/install-*.sh

# Create install wrapper that simulates systemd environment
RUN mkdir -p /etc/systemd/system && \
    echo '#!/bin/bash\necho "systemctl: simulated for Docker build"\nexit 0' > /usr/bin/systemctl-fake && \
    chmod +x /usr/bin/systemctl-fake

# Install both applications (they'll create service files but won't start)
RUN bash /tmp/install-ais-catcher.sh _ -p || true
RUN bash /tmp/install-ais-control.sh || true

# Clean up
RUN rm -f /tmp/install-*.sh

# -------------------
# Stage 3: Final runtime image
# -------------------
FROM systemd-base AS runtime

# Copy installed files from installer stage
COPY --from=installer /usr/local /usr/local
COPY --from=installer /etc/systemd/system /etc/systemd/system
COPY --from=installer /lib/systemd/system /lib/systemd/system
COPY --from=installer /var/lib /var/lib
COPY --from=installer /opt /opt

# Enable services
RUN systemctl enable ais-catcher.service || true
RUN systemctl enable ais-catcher-control.service || true

# Expose port for web interface
EXPOSE 8100

# Use systemd as init system
STOPSIGNAL SIGRTMIN+3
VOLUME ["/sys/fs/cgroup"]

CMD ["/lib/systemd/systemd"]
