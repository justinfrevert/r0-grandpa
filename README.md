# RISC Zero Grandpa
Generate easily verifiable proofs of valid Substrate GRANDPA finality.

This project is still under development and is not yet ready for production use. It is difficult to use at the moment without a slightly customized node with particular state.

### Substrate installation
https://docs.substrate.io/install/br

### Risc Zero installation
```shell
cargo binstall cargo-risczero
cargo risczero install
```

### Subxt(Substrate node client)
https://github.com/paritytech/subxt

### Starting a node
TBD

### Custom metadata
```shell
subxt metadata > example_metadata.scale
```

## Building
```shell
cargo build --release
```

### Common Issues

Error: "Block not covered by..."
Solution: Wait until the first session has completed.