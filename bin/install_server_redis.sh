#!/bin/bash

set -e
set -x

# REDIS #
mkdir -p ../db
test ! -d ../redis/ && git clone https://github.com/antirez/redis.git ../redis
pushd ../redis/
git checkout 5.0
make
popd
