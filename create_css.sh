#!/bin/bash

# Download Tailwind CSS standalone CLI if it doesn't exist
if [ ! -f "./tailwindcss-linux-x64" ]; then
    echo "Downloading Tailwind CSS standalone CLI..."
    curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64
    chmod +x tailwindcss-linux-x64
fi

# Build the CSS
./tailwindcss-linux-x64 -i ./static/css/styles.css -o ./static/css/tailwind.css --minify
