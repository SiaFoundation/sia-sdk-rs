use crate::encoding::SiaEncodable;
use crate::encoding_async::{AsyncSiaDecodable, AsyncSiaDecode, AsyncSiaEncodable, AsyncSiaEncode};
use crate::types::v2::NetAddress;
use blake2b_simd::Params;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::signing::{PrivateKey, PublicKey, Signature};
use crate::types::{Address, Currency, Hash256};

pub const SEGMENT_SIZE: usize = 64;
pub const SECTOR_SIZE: usize = 1 << 22;
pub const LEAVES_PER_SECTOR: usize = SECTOR_SIZE / SEGMENT_SIZE;

/// Represents a host in the Sia network. The
/// addresses can be used to connect to the host.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    pub public_key: PublicKey,
    pub addresses: Vec<NetAddress>,
    pub country_code: String,
    pub latitude: f64,
    pub longitude: f64,
}

/// Contains the prices and parameters of a host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, AsyncSiaEncode, AsyncSiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct HostPrices {
    /// The price of forming a new contract with the host.
    pub contract_price: Currency,
    /// The collateral per byte per block the host will
    /// risk for stored data.
    pub collateral: Currency,
    /// The cost of storing a sector on the host per byte per block.
    pub storage_price: Currency,
    /// The cost of uploading data to the host per byte.
    pub ingress_price: Currency,
    /// The cost of downloading data from the host per byte.
    pub egress_price: Currency,
    /// The cost to remove a sector from a contract.
    pub free_sector_price: Currency,
    /// The current height of the host's blockchain.
    pub tip_height: u64,
    /// The time until which the prices are valid.
    pub valid_until: DateTime<Utc>,

    pub signature: Signature,
}

impl HostPrices {
    /// Computes the signature hash for the host prices.
    pub fn sig_hash(&self) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        self.contract_price.encode(&mut state).unwrap();
        self.collateral.encode(&mut state).unwrap();
        self.storage_price.encode(&mut state).unwrap();
        self.ingress_price.encode(&mut state).unwrap();
        self.egress_price.encode(&mut state).unwrap();
        self.free_sector_price.encode(&mut state).unwrap();
        self.tip_height.encode(&mut state).unwrap();
        self.valid_until.encode(&mut state).unwrap();
        state.finalize().into()
    }

    /// Checks if the prices are valid for the given host key and timestamp.
    pub fn is_valid(&self, host_key: &PublicKey, timestamp: DateTime<Utc>) -> bool {
        self.valid_until > timestamp
            && self.tip_height > 0
            && host_key.verify(self.sig_hash().as_ref(), &self.signature)
    }
}

/// Contains the settings of a host, including its prices and other parameters.
#[derive(Debug, PartialEq, Serialize, Deserialize, AsyncSiaEncode, AsyncSiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct HostSettings {
    /// The version of the protocol the host is using.
    pub protocol_version: [u8; 3],
    /// The current release the host is running.
    pub release: String,
    /// The wallet address of the host to use for contract payments.
    pub wallet_address: Address,
    /// If the host is accepting new contracts.
    pub accepting_contracts: bool,
    /// The maximum amount of collateral that the host will accept for a
    /// single contract.
    pub max_collateral: Currency,
    /// The maximum duration, in blocks, that the host will accept for a contract.
    pub max_contract_duration: u64,
    /// The amount of storage, in sectors, that the host has available.
    pub remaining_storage: u64,
    /// The total amount of storage, in sectors, that the host is offering.
    pub total_storage: u64,
    /// The current prices of the host
    pub prices: HostPrices,
}

/// An account token is used to pay for RPC calls that do not
/// require a contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, AsyncSiaEncode, AsyncSiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct AccountToken {
    pub host_key: PublicKey,
    pub account: PublicKey,
    pub valid_until: DateTime<Utc>,

    pub signature: Signature,
}

impl AccountToken {
    fn compute_sig_hash(
        host_key: &PublicKey,
        account: &PublicKey,
        valid_until: &DateTime<Utc>,
    ) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        host_key.encode(&mut state).unwrap();
        account.encode(&mut state).unwrap();
        valid_until.encode(&mut state).unwrap();
        state.finalize().into()
    }

    pub fn new(account_key: &PrivateKey, host_key: PublicKey) -> Self {
        let expiration_time = chrono::Utc::now() + chrono::Duration::minutes(5);
        let sig_hash =
            Self::compute_sig_hash(&host_key, &account_key.public_key(), &expiration_time);
        AccountToken {
            host_key,
            account: account_key.public_key(),
            valid_until: expiration_time,

            signature: account_key.sign(sig_hash.as_ref()),
        }
    }
}

/// An AccountDeposit is an amount of Siacoin to be deposited into an account.
#[derive(Debug, PartialEq, Serialize, Deserialize, AsyncSiaEncode, AsyncSiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct AccountDeposit {
    pub account: PublicKey,
    pub amount: Currency,
}
