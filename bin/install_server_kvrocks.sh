#!/bin/bash

set -e
set -x

# KVROCKS #
mkdir -p ../db
test ! -d ../kvrocks/ && git clone https://github.com/apache/incubator-kvrocks.git ../kvrocks 
pushd ../kvrocks/
git checkout 2.0 
make -j4
popd
