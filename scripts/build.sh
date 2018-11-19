#!/usr/bin/env bash

set -x;

if [ "${TRAVIS_OS_NAME}" == "osx" ]; then
    cargo test --release --verbose;
elif [ "${TRAVIS_OS_NAME}" == "linux" ]; then
    version=$(cat Cargo.toml | grep "^version" | awk '{ print $3 }' | sed 's/\"//g');
    docker run --rm -v "$PWD":/usr/src/crust jacderida/crust-ci:$version;
fi
