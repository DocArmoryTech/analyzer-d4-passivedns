#!/bin/bash

set -e
set -x

# Change to the script's directory
cd "$(dirname "$0")"

# Install system dependencies
sudo apt-get install -y python3-pip screen build-essential git

# Install kvrocks (relative to project root)
mkdir -p ../db
if [ ! -d "../kvrocks" ]; then
    git clone https://github.com/apache/incubator-kvrocks.git ../kvrocks
fi
cd ../kvrocks
git checkout 2.0
make -j4
cd ..
