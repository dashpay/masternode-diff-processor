#!/bin/bash

# run tests
cargo test --package dash-spv-masternode-processor --lib tests --verbose

# shellcheck disable=SC2181
if [ $? -eq 0 ]
then
  echo "Tests: OK"
else
  echo "Tests: failed" >&2
  exit 1
fi

# build iOS & MacOS binaries
cargo +nightly lipo --release
cargo +nightly build --target=x86_64-apple-darwin --release
cargo +nightly build --target=aarch64-apple-darwin --release
lipo -create target/aarch64-apple-darwin/release/libdash_spv_masternode_processor.a target/x86_64-apple-darwin/release/libdash_spv_masternode_processor.a -output target/universal/release/libdash_spv_masternode_processor_macos.a

# Assume we have structure like this:
# dash/masternodes-diff-processor/...
# dash/DashSync/...
#cp -p target/universal/release/libdash_spv_masternode_processor.a ../DashSync/DashSync/lib/libdash_spv_masternode_processor_ios.a
#cp -p target/universal/release/libdash_spv_masternode_processor_macos.a ../DashSync/DashSync/lib/libdash_spv_masternode_processor_macos.a
#cp -p target/dash_spv_masternode_processor.h ../DashSync/DashSync/shared/crypto/
