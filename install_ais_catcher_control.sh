#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# ============================
# Configuration Variables
# ============================

# GitHub repository details
GITHUB_USER="jvde-github"
GITHUB_REPO="AIS-catcher-control"
RELEASE_TAG="v0.1"

# Name for the systemd service
SERVICE_NAME="ais-catcher-control"

# Name of the binary after installation
BIN_NAME="AIS-catcher-control"

# Installation path
INSTALL_PATH="/usr/bin/${BIN_NAME}"

# ============================
# Function Definitions
# ============================

# Function to print messages
print_message() {
  echo "========================================"
  echo "$1"
  echo "========================================"
}

# Function to check if a command exists
command_exists() {
  command -v "$1" &> /dev/null
}

# Function to install dependencies
install_dependencies() {
  print_message "Checking and installing dependencies..."

  if ! command_exists curl; then
    print_message "Installing curl..."
    apt update
    apt install -y curl
  fi

  if ! command_exists jq; then
    print_message "Installing jq..."
    apt update
    apt install -y jq
  fi

  if ! command_exists systemctl; then
    print_message "systemctl not found. Ensure you're running a system with systemd."
    exit 1
  fi

  if ! command_exists ss; then
    print_message "Installing iproute2 for 'ss' command..."
    apt update
    apt install -y iproute2
  fi
}

# Function to detect CPU architecture
detect_architecture() {
  ARCH=$(uname -m)
  if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    BINARY_SUFFIX="arm64"
  elif [[ "$ARCH" == "armv6l" || "$ARCH" == "armv7l" || "$ARCH" == "armhf" ]]; then
    BINARY_SUFFIX="armhf"
  else
    print_message "Unsupported architecture: $ARCH"
    exit 1
  fi

  print_message "Detected architecture: $ARCH ($BINARY_SUFFIX)"
}

# Function to download the appropriate binary
download_binary() {
  print_message "Fetching latest release information from GitHub..."

  RELEASE_JSON=$(curl -s "https://api.github.com/repos/${GITHUB_USER}/${GITHUB_REPO}/releases/tags/${RELEASE_TAG}")

  if [[ $(echo "$RELEASE_JSON" | jq -r '.message') == "Not Found" ]]; then
    print_message "Release tag ${RELEASE_TAG} not found in repository ${GITHUB_USER}/${GITHUB_REPO}."
    exit 1
  fi

  DOWNLOAD_URL=$(echo "$RELEASE_JSON" | jq -r ".assets[] | select(.name | test(\"${BINARY_SUFFIX}\")) | .browser_download_url")

  if [[ -z "$DOWNLOAD_URL" || "$DOWNLOAD_URL" == "null" ]]; then
    print_message "Could not find a download URL for architecture: ${BINARY_SUFFIX}"
    exit 1
  fi

  print_message "Found download URL: $DOWNLOAD_URL"

  # Create a temporary directory for downloading the binary
  TEMP_DIR=$(mktemp -d)
  trap 'rm -rf -- "$TEMP_DIR"' EXIT

  print_message "Downloading the binary to temporary directory..."
  curl -L "$DOWNLOAD_URL" -o "${TEMP_DIR}/${BIN_NAME}"

  # Verify the binary was downloaded
  if [[ ! -f "${TEMP_DIR}/${BIN_NAME}" ]]; then
    print_message "Failed to download the binary."
    exit 1
  fi
}

# Function to install the binary
install_binary() {
  print_message "Installing the binary to ${INSTALL_PATH}..."

  # Stop the ais-catcher-control service if it is active
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    print_message "Stopping existing ${SERVICE_NAME} service..."
    systemctl stop "${SERVICE_NAME}"
  fi
  
  # Check if port 8110 is free
  if ss -tulpn | grep -q ":8110"; then
    print_message "Port 8110 is in use. Please free up the port before proceeding."
    exit 1
  else
    print_message "Port 8110 is free."
  fi
  
  mv "${TEMP_DIR}/${BIN_NAME}" "${INSTALL_PATH}"
  chmod +x "${INSTALL_PATH}"

  print_message "Binary installed successfully at ${INSTALL_PATH}."
}

create_systemd_service() {
  SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

  print_message "Creating systemd service file at ${SERVICE_FILE}..."

  # Always create/overwrite the service file with the new configuration
  cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=AIS-catcher Control Service
After=network.target

[Service]
ExecStart=${INSTALL_PATH}
Type=simple
Restart=always
# Restart after 10 seconds if the service crashes
RestartSec=10
# Limit restart attempts to 3 times per 60 seconds
StartLimitInterval=60
StartLimitBurst=3
User=root
Environment=GO_ENV=production
WorkingDirectory=/root

[Install]
WantedBy=multi-user.target
EOF

  # Set proper permissions for the service file
  chmod 644 "$SERVICE_FILE"

  print_message "Systemd service file created with restart rate limiting."
}

# Function to check prerequisites
check_prerequisites() {
  print_message "Checking prerequisites..."

  # Check if 'ais-catcher' service exists
  if ! systemctl list-unit-files | grep -q "^ais-catcher.service"; then
    print_message "The 'ais-catcher' service does not exist. Please install 'ais-catcher' before proceeding."
    exit 1
  else
    print_message "'ais-catcher' service is installed."
  fi

  # Check if directory '/etc/AIS-catcher/' exists with required files
  if [[ ! -d "/etc/AIS-catcher" ]]; then
    print_message "Directory '/etc/AIS-catcher/' does not exist."
    exit 1
  fi

  if [[ ! -f "/etc/AIS-catcher/config.json" || ! -f "/etc/AIS-catcher/config.cmd" ]]; then
    print_message "Required configuration files 'config.json' or 'config.cmd' are missing in '/etc/AIS-catcher/'."
    exit 1
  else
    print_message "Required configuration files are present."
  fi
}

# Function to enable and start the service
enable_and_start_service() {
  print_message "Reloading systemd daemon..."
  systemctl daemon-reload

  print_message "Enabling ${SERVICE_NAME} service to start on boot..."
  systemctl enable "${SERVICE_NAME}"

  print_message "Starting ${SERVICE_NAME} service..."
  systemctl start "${SERVICE_NAME}"

  print_message "Checking the status of the ${SERVICE_NAME} service..."
  systemctl status "${SERVICE_NAME}" --no-pager

  print_message "Installation and setup complete. The ${SERVICE_NAME} service is active and running."
}

# ============================
# Script Execution Starts Here
# ============================

# Ensure the script is run as root
if [[ "$EUID" -ne 0 ]]; then
  print_message "Please run this script as root or with sudo."
  exit 1
fi

install_dependencies
detect_architecture
check_prerequisites
download_binary
install_binary
create_systemd_service
enable_and_start_service
