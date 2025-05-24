#!/bin/bash

# Start the Performance Server

echo "🚀 Starting Phishing Detector Performance Server..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Run ./setup_server.sh first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Start the server
python performance_server.py
