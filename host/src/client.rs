use std::str::FromStr;
use std::time::Duration;

use sp_core::{sr25519};
use sp_core::Pair as PairT;
use subxt::config::substrate;
use subxt::Config;
use subxt::OnlineClient;

use derive_where::derive_where;
use sp_core::ed25519::{Pair, Public, Signature};
use subxt::backend::legacy::rpc_methods::{BlockNumber, NumberOrHex};
use subxt::backend::rpc::RawValue;
use subxt::backend::rpc::RpcClient;
use subxt::SubstrateConfig;

use parity_scale_codec::{Decode, Encode};

// Must replace with your node's metadata
#[subxt::subxt(runtime_metadata_path = "./example_metadata.scale")]
mod substrate_node {}

use substrate_node::runtime_types::sp_runtime::generic::header::Header;

// More concrete copy of Substrate's Finality Proof, for encoding in the context of this client
#[derive(Debug, PartialEq, Encode, Decode, Clone)]
pub struct FinalityProof<Header, Hash> {
    /// The hash of block F for which justification is provided.
    pub block: Hash,
    /// Justification of the block F.
    pub justification: Vec<u8>,
    /// The set of headers in the range (B; F] that we believe are unknown to the caller. Ordered.
    pub unknown_headers: Vec<Header>,
}

// More concrete copy of Substrate's Grandpa Justification, for encoding in the context of this client
#[derive(Encode, Decode, Clone, Debug)]
pub struct GrandpaJustification<Header, Hash, Number> {
    /// The round (voting period) this justification is valid for.
    pub round: u64,
    /// The set of votes for the chain which is to be finalized.
    pub commit: finality_grandpa::Commit<Hash, Number, Signature, Public>,
    /// A proof that the chain of blocks in the commit are related to each other.
    pub votes_ancestries: Vec<Header>,
}

pub type Message = Vec<u8>;


// Custom Subxt methods for grandpa RPC
#[derive_where(Clone, Debug)]
pub struct LegacyRpcMethods<T> {
    pub client: RpcClient,
    _marker: std::marker::PhantomData<T>,
}

impl<T: Config> LegacyRpcMethods<T> {
    /// Instantiate the legacy RPC method interface.
    pub fn new(client: RpcClient) -> Self {
        LegacyRpcMethods {
            client,
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn grandpa_proveFinality(&self, block_number: Option<BlockNumber>) -> Box<RawValue> {
        use subxt::rpc_params;
        let params = rpc_params![block_number];
        let finality_proof = self
            .client
            .request_raw("grandpa_proveFinality", params.build())
            .await
            .unwrap();
        finality_proof
    }

    pub async fn chain_getFinalizedHead(&self) -> Box<RawValue> {
        use subxt::rpc_params;
        let params = rpc_params![];
        let finalized_head = self
            .client
            .request_raw("chain_getFinalizedHead", params.build())
            .await
            .unwrap();
        finalized_head
    }

	pub async fn chain_getBlock(&self, block_hash: Box<RawValue>) -> Box<RawValue> {
        use subxt::rpc_params;
        let params = rpc_params![block_hash];
        let block = self
            .client
            .request_raw("chain_getBlock", params.build())
            .await
            .unwrap();
        block
    }

}

#[derive(Clone, Debug)]
pub struct OnchainProof {
	signature: Signature,
	message: Message,
	authority: Public,
}

// Extract values from onchain proof
pub async fn get_finality_proof(rpc_url: String, block_number: u64) -> Vec<GuestProof> {
    use subxt::ext::subxt_core::utils::H256;
    let rpc_client = RpcClient::from_url(&rpc_url).await.unwrap();
    let rpc = LegacyRpcMethods::<SubstrateConfig>::new(rpc_client.clone());
    let api = OnlineClient::<SubstrateConfig>::from_rpc_client(rpc_client.clone())
        .await
        .unwrap();

    let finality_proof = rpc
        .grandpa_proveFinality(Some(NumberOrHex::Number(block_number.into())))
        .await;

    let finality_proof_str = finality_proof.get();
    let trimmed = &finality_proof_str[3..finality_proof_str.len() - 1];

    // Ensure it's not an empty proof; indicates some finality misconfiguration
    assert!(trimmed.len() != 0);

    let hex_decoded_finality_proof = hex::decode(trimmed).unwrap();

    let finality_proof: FinalityProof<Header<u32>, H256> =
        FinalityProof::decode(&mut &hex_decoded_finality_proof[..]).unwrap();

    let justification: GrandpaJustification<Header<u32>, H256, u32> =
        Decode::decode(&mut &finality_proof.justification[..]).unwrap();

    let block_hash_query = substrate_node::storage()
        .system()
        .block_hash(block_number as u32);

    let block_hash = api
        .storage()
        .at_latest()
        .await
        .unwrap()
        .fetch(&block_hash_query)
        .await
        .unwrap()
        // Get value out of option
        .unwrap();

    let set_id_storage_query = substrate_node::storage().grandpa().current_set_id();
    let set_id = api
        .storage()
        .at(block_hash)
        .fetch(&set_id_storage_query)
        .await
        .unwrap();

    let authorities_query = substrate_node::storage()
        .grandpa()
        .authorities();

    let authorities: Vec<Public> = api
        .storage()
        .at(block_hash)
        .fetch(&authorities_query)
        .await
        .unwrap()
        .expect("Onchain authorities should always exist").0
        .into_iter()
        .map(|authority_with_weight| {
            Public::from_raw(authority_with_weight.0.0)
        })
        .collect();


    let round = justification.round;

    let verification_data: Vec<GuestProof> = justification
        .commit
        .precommits
        .iter()
        .enumerate()
        .map(|(i, signed_precommit)| {
            let msg = finality_grandpa::Message::Precommit(signed_precommit.precommit.clone());
            let payload = sp_consensus_grandpa::localized_payload(round, set_id.unwrap(), &msg);
            let signature = signed_precommit.signature.clone();
			// TODO: Do verification optionally
			// let is_verified = Pair::verify(&signed_precommit.signature, &payload[..], &authority);
			// assert!(is_verified);

			let onchain_proof = OnchainProof { signature, message: payload, authority: authorities[i] };

			let guest_proof = GuestProof::from(onchain_proof.clone());
			assert!(guest_proof.verify());

			// onchain_proof
			guest_proof
        })
        .collect();

    verification_data
}

// pub struct GuestProof(ed25519_dalek::Signature, Message, ed25519_dalek::VerifyingKey);
pub struct GuestProof(
	pub ed25519_dalek::VerifyingKey,
	pub Message,
	pub ed25519_dalek::Signature);

impl GuestProof {
	pub fn verify(&self) -> bool {
		use ed25519_dalek::Verifier;
		ed25519_dalek::VerifyingKey::verify(&self.0, &self.1, &self.2).is_ok()
	}
}

impl From<OnchainProof> for GuestProof {
	fn from(onchain_proof: OnchainProof) -> Self {
		let dalek_signature = ed25519_dalek::Signature::from_bytes(&onchain_proof.signature.0);
		let dalek_authority = ed25519_dalek::VerifyingKey::from_bytes(&onchain_proof.authority.0).unwrap();
		GuestProof(dalek_authority, onchain_proof.message, dalek_signature)
	}
}	
