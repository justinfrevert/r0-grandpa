// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use clap::Parser;
use methods::{R0_GRANDPA_GUEST_ELF, R0_GRANDPA_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};

mod client;

#[derive(Parser, Clone)]
#[command(version, about, long_about = None)]
struct Cli {
    /// RPC URL of the Substrate node
    #[arg(short, long, default_value = "ws://127.0.0.1:9944", env)]
    rpc_url: String,

    #[arg(short, long, env)]
    block_number: u64,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    client::get_finality_proof(cli.rpc_url, cli.block_number).await;

    // For example:
    let input: u32 = 15 * u32::pow(2, 27) + 1;
    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Proof information by proving the specified ELF binary.
    // This struct contains the receipt along with statistics about execution of the guest
    let prove_info = prover.prove(env, R0_GRANDPA_GUEST_ELF).unwrap();

    // extract the receipt.
    let receipt = prove_info.receipt;

    // TODO: Implement code for retrieving receipt journal here.

    // For example:
    let _output: u32 = receipt.journal.decode().unwrap();

    // The receipt was verified at the end of proving, but the below code is an
    // example of how someone else could verify this receipt.
    receipt.verify(R0_GRANDPA_GUEST_ID).unwrap();
}
