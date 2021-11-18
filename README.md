# masternode-diff-message-processor
Library for processing masternode diff messages
WORK IN PROGRESS!
# TODO
1. Create integration with BLS signatures
2. Now it will be necessary to figure out what to do with the external libraries used, keeping in mind our policy regarding this.
3. Check for memory leaks
4. Write additional integration tests


Prepare:
Install libsodium before build
Run tests: 
cargo test --package masternodes-diff-processor --lib tests
