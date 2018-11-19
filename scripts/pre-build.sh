#!/usr/bin/env bash

set -x

if [ "${TRAVIS_OS_NAME}" == "osx" ]; then
    curl -sSL https://github.com/maidsafe/QA/raw/master/travis/cargo_install.sh > cargo_install.sh
    bash cargo_install.sh cargo-prune
elif [ "${TRAVIS_OS_NAME}" == "linux" ]; then
    version=$(cat Cargo.toml | grep "^version" | awk '{ print $3 }' | sed 's/\"//g')
    docker pull jacderida/crust:$version
fi
