# masternode-diff-message-processor
Library for processing masternode diff messages
WORK IN PROGRESS!
# TODO
1. Create integration with BLS signatures
2. Now it will be necessary to figure out what to do with the external libraries used, keeping in mind our policy regarding this.
3. Increase code coverage

Run tests: 
cargo test --package dash_mndiff --lib tests

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


