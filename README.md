# masternode-diff-message-processor

Library for processing masternode diff messages

| main | [![Tests](https://github.com/dashpay/masternode-diff-processor/workflows/Tests/badge.svg?branch=main)](https://github.com/dashpay/masternode-diff-processor/actions) | [![codecov](https://codecov.io/gh/dashpay/masternode-diff-processor/branch/main/graph/badge.svg)](https://codecov.io/gh/dashpay/masternode-diff-processor) | ![Lint](https://github.com/dashpay/masternode-diff-processor/workflows/Lint/badge.svg) |
# TODO
1. Create integration with BLS signatures
2. Now it will be necessary to figure out what to do with the external libraries used, keeping in mind our policy regarding this.
3. Increase code coverage

Run tests: 
cargo test --package dash-spv-masternode-processor --lib tests
Run c test-like functions:
./build.sh && clang c/main.c target/universal/release/libdash_spv_masternode_processor_macos.a -o test && ./test

For fast local testing:
In 'dash-shared-core'
1) Create custom branch
2) Modify DashSharedCore.podspec so 'source' points to branch from previous step
3) Modify Cargo.toml so needed dependency points to desired branch

In 'masternodes-diff-processor':
1) Don't forget to push the changes into the branch that 'dash-shared-core' is looking at

In 'DashSync' when building example app:
1) In Podfile put 'DashSharedCore' pod which is 'dash-shared-core' looking at right above 'DashSync' pod import
2) Perform 'pod cache clean DashSharedCore' if neccessary 
3) Run 'pod update'


