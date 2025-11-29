# -------------------
# AIS-catcher + Control Panel Container
# -------------------
FROM debian:bookworm-slim

# Install systemd and dependencies for install scripts
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

# Install AIS-catcher using official install script
RUN bash -c "$(curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher/main/scripts/aiscatcher-install) _ -p"

# Install AIS-catcher-control using official install script
RUN bash -c "$(curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher-control/main/install_ais_catcher_control.sh)"

# Expose port for web interface
EXPOSE 8100

# Use systemd as init system
STOPSIGNAL SIGRTMIN+3

# Start systemd
CMD ["/lib/systemd/systemd"]
