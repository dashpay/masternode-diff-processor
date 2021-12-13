#!/bin/bash

# run tests
cargo test --package dash_mndiff --lib tests --verbose

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
lipo -create target/aarch64-apple-darwin/release/libmndiff_ios.a target/x86_64-apple-darwin/release/libmndiff_ios.a -output target/universal/release/libmndiff_macos.a

# Assume we have structure like this:
# dash/masternodes-diff-processor/...
# dash/DashSync/...
cp -Rp target/universal/release/*.a ../DashSync/DashSync/lib/
cp -p target/mndiff.h ../DashSync/DashSync/shared/crypto/
