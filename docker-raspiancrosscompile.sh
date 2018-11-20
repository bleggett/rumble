#!/bin/bash

# Run this from the directory where your `Cargo.toml` lives
# `docker-raspiancrosscompile.sh <cargo subcommand, e.g. 'build --release'>`

RUST_CCIMG='ragnaroek/rust-raspberry:1.30.1'

docker pull $RUST_CCIMG

docker run -t -v "$(pwd)":/home/cross/project -v ~/.cargo/registry:/home/cross/.cargo/registry $RUST_CCIMG $1
