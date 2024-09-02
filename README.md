# RISC Zero Rust Starter Template

### Substrate installation
https://docs.substrate.io/install/br

### Risc Zero installation
cargo binstall cargo-risczero
    cargo risczero install

### Subxt(Substrate node client)
https://github.com/paritytech/subxt

### Starting a node
`./target/release/substrate-node --dev --state-pruning archive --blocks-pruning archive`

### Custom metadata
`subxt metadata > example_metadata.scale`