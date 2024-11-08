use crate::encoding::{
    SiaDecodable, SiaDecode, SiaEncodable, SiaEncode, V1SiaDecodable, V1SiaDecode, V1SiaEncodable,
    V1SiaEncode,
};
use crate::merkle::{Accumulator, LEAF_HASH_PREFIX};
use crate::signing::PublicKey;
use crate::specifier::{specifier, Specifier};
use crate::{Address, HexParseError};
use blake2b_simd::Params;
use core::fmt;
use serde::de::Error;
use serde::{Deserialize, Serialize};

pub const ALGORITHM_ED25519: Specifier = specifier!["ed25519"];

/// A generic public key that can be used to spend a utxo or revise a file
///  contract
///
/// Currently only supports ed25519 keys
#[derive(Debug, PartialEq, Clone, SiaEncode, V1SiaEncode, SiaDecode, V1SiaDecode)]
pub struct UnlockKey {
    pub algorithm: Specifier,
    pub key: Vec<u8>,
}

impl Serialize for UnlockKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        String::serialize(&self.to_string(), serializer)
    }
}

impl<'de> Deserialize<'de> for UnlockKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            UnlockKey::parse_string(&s).map_err(|e| Error::custom(format!("{:?}", e)))
        } else {
            let (algorithm, key) = <(Specifier, Vec<u8>)>::deserialize(deserializer)?;
            Ok(Self { algorithm, key })
        }
    }
}

impl fmt::Display for UnlockKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, hex::encode(self.key.as_slice()))
    }
}

impl UnlockKey {
    /// Parses an UnlockKey from a string
    /// The string should be in the format "algorithm:public_key"
    pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
        let (prefix, key_str) = s.split_once(':').ok_or(HexParseError::MissingPrefix)?;
        Ok(UnlockKey {
            algorithm: Specifier::from(prefix),
            key: hex::decode(key_str).map_err(HexParseError::HexError)?,
        })
    }
}

impl From<PublicKey> for UnlockKey {
    fn from(val: PublicKey) -> Self {
        UnlockKey {
            algorithm: ALGORITHM_ED25519,
            key: val.as_ref().to_vec(),
        }
    }
}

// specifies the conditions for spending an output or revising a file contract.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, SiaEncode, SiaDecode, V1SiaEncode, V1SiaDecode,
)]
#[serde(rename_all = "camelCase")]
pub struct UnlockConditions {
    pub timelock: u64,
    pub public_keys: Vec<UnlockKey>,
    pub signatures_required: u64,
}

impl UnlockConditions {
    pub fn new(
        timelock: u64,
        public_keys: Vec<UnlockKey>,
        required_signatures: u64,
    ) -> UnlockConditions {
        UnlockConditions {
            timelock,
            public_keys,
            signatures_required: required_signatures,
        }
    }

    pub fn standard_unlock_conditions(public_key: PublicKey) -> UnlockConditions {
        UnlockConditions {
            timelock: 0,
            public_keys: vec![public_key.into()],
            signatures_required: 1,
        }
    }

    pub fn address(&self) -> Address {
        let mut acc = Accumulator::new();
        let mut p = Params::new();
        p.hash_length(32);

        let h = p
            .to_state()
            .update(LEAF_HASH_PREFIX)
            .update(&self.timelock.to_le_bytes())
            .finalize();

        acc.add_leaf(&h.into());

        for key in self.public_keys.iter() {
            let mut state = p.to_state();
            state.update(LEAF_HASH_PREFIX);
            key.encode(&mut state).unwrap();

            let h = state.finalize();
            acc.add_leaf(&h.into());
        }

        let h = p
            .to_state()
            .update(LEAF_HASH_PREFIX)
            .update(&self.signatures_required.to_le_bytes())
            .finalize();

        acc.add_leaf(&h.into());

        Address::new(acc.root().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::Seed;

    #[test]
    fn test_serialize_unlock_key() {
        let unlock_key: UnlockKey = PublicKey::new([
            0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b, 0x47, 0xda,
            0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28, 0x8c, 0x1a, 0xd0, 0xdb,
            0x1d, 0x1c, 0xe1, 0xb6,
        ])
        .into();

        // binary
        let mut unlock_key_serialized: Vec<u8> = Vec::new();
        unlock_key.encode(&mut unlock_key_serialized).unwrap();
        assert_eq!(
            unlock_key_serialized,
            [
                0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a, 0xac, 0x1f, 0xfb,
                0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b, 0x47, 0xda, 0x1d, 0x56, 0x7e, 0x35,
                0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28, 0x8c, 0x1a, 0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6
            ]
        );
        //assert_eq!(unlock_key_deserialized, unlock_key);

        // json
        let unlock_key_serialized = serde_json::to_string(&unlock_key).unwrap();
        let unlock_key_deserialized: UnlockKey =
            serde_json::from_str(&unlock_key_serialized).unwrap();
        assert_eq!(
            unlock_key_serialized,
            "\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\""
        );
        assert_eq!(unlock_key_deserialized, unlock_key);
    }

    #[test]
    fn test_serialize_unlock_conditions() {
        let unlock_conditions = UnlockConditions::new(
            123,
            vec![PublicKey::new([
                0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b, 0x47, 0xda,
                0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28, 0x8c, 0x1a, 0xd0, 0xdb,
                0x1d, 0x1c, 0xe1, 0xb6,
            ])
            .into()],
            1,
        );

        // binary
        let mut unlock_conditions_serialized: Vec<u8> = Vec::new();
        unlock_conditions
            .encode(&mut unlock_conditions_serialized)
            .unwrap();

        assert_eq!(
            unlock_conditions_serialized,
            [
                123, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 101, 100, 50, 53, 53, 49, 57, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 154, 172, 31, 251, 28, 253, 16,
                121, 168, 198, 200, 123, 71, 218, 29, 86, 126, 53, 185, 114, 52, 153, 60, 40, 140,
                26, 208, 219, 29, 28, 225, 182, 1, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        //assert_eq!(unlock_conditions_deserialized, unlock_conditions);

        // json
        let unlock_conditions_serialized = serde_json::to_string(&unlock_conditions).unwrap();
        let unlock_conditions_deserialized: UnlockConditions =
            serde_json::from_str(&unlock_conditions_serialized).unwrap();
        assert_eq!(unlock_conditions_serialized, "{\"timelock\":123,\"publicKeys\":[\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\"],\"signaturesRequired\":1}");
        assert_eq!(unlock_conditions_deserialized, unlock_conditions);
    }

    #[test]
    fn test_standard_unlockhash() {
        let test_cases = vec![
            (
                "80f637df83a93a6916d1b5c8bdbb061f967fb9fe8fe51ef4d97eeec73c6bfc394771e4a04f42",
                hex::decode("ad08d551ab7116b8c2285de81ffa528ef3679f9e242c3f551b560a60ab9763db")
                    .unwrap(),
            ),
            (
                "99a27a168bdde2e9c59bc967f6c662e3db0b2cf13da26ddae26004fa19c61d3db017dca7d0d3",
                hex::decode("18ac9c05b0c5e7c62859812b943572429cda178aa3df92697569b8984c603b4c")
                    .unwrap(),
            ),
            (
                "128151658b256d0185f3f91504758349a96e73c1a68a39c7ff7bf9d0e416997c964d773858ce",
                hex::decode("2b36cc860796f2e8a1990b437f46a4b905840e6ba41ba5f68fe2b8ebe23626af")
                    .unwrap(),
            ),
            (
                "1f47d453cfd7369bce4034d3ab461feb2a4d073bf59c959225993d00e38d71a8fea7c57cd3f1",
                hex::decode("a3e3c2f3493a079d3dfe69681bf878c59337e3d1c79d17a34e3da81f062bbe21")
                    .unwrap(),
            ),
            (
                "e03c56f8d95894cea875711e2f909c68c07dd37142a8253813ad09abceb2b6e5dd89992c9638",
                hex::decode("a03d3b27db7e143cb8b39a1eb9234bffad59d6f50adf4f0ee916afd510a939a0")
                    .unwrap(),
            ),
            (
                "68b6dd2e50f12e2deef2efd6b7baa660d87950ea16c5a8402a6db5873e062bcdd5246940b44e",
                hex::decode("52e4438ca9b6eb2d33953f97255e410130d55749432094fe9963f4fc65167ce5")
                    .unwrap(),
            ),
            (
                "c766e0a5ef49b7bab6c2e9c6a0b699e87eb3580e08f3fe77648dd93b66795a8606787cc5e29e",
                hex::decode("4110f8b0ade1cca7aa40008a9b9911655393288eaacc3948fecd13edd3f092ec")
                    .unwrap(),
            ),
            (
                "b455cf3c22de0d84ab8599499b0c2056d4916ab4c642b6b716148487f83ca5a85ad199b7a454",
                hex::decode("861d50c4ee90b0a6a5544a3820978dad1fd9391c4813ede9e4963f0d6bec010a")
                    .unwrap(),
            ),
            (
                "5274e9f3db1acfe8bb2d67dbbb5b6f2cc20769a0b42c8a9187ae827bf637f06e62ecada30f9f",
                hex::decode("a5329c135951f3505d9a26d2833cb6c1aebb875fbada80f38b09bd3314f26802")
                    .unwrap(),
            ),
            (
                "1540f42840b0479b238ec0143984a784c58240a8ca5e21da4b66be89a2f54353c99739938947",
                hex::decode("e11589e1857b7a0d2fc3526fbdfdc4d4708dfbf251184be1118138df4ef2d47e")
                    .unwrap(),
            ),
            (
                "21592f041e6f6861f199d54a26fe6bdfc5d629bb5dda12058d3ce28549c4aeffdbbdb67c2b95",
                hex::decode("d57887af5b838ea2d20a582f659b3e36ca47d33b253364e3b774a1f4feb8415b")
                    .unwrap(),
            ),
            (
                "f34b1e0b74a695f8bc82a97bab3b9d1ebe420956cbb3f7611c349c9659ba13fa362a417b1fd2",
                hex::decode("5da4058d2f95e3c547aab8b5c70817ed3795856aa7988676f266cb429d75ce06")
                    .unwrap(),
            ),
            (
                "3549a1680fcc093347e2674f4e89c84200965e1b779e2b3c05e4b21645a0b2fd5ac86923ef7a",
                hex::decode("98ced26430f3be35b29ca76d3f65ea616f89e2510a3c1307856522e23057d958")
                    .unwrap(),
            ),
            (
                "86fc291f7f53def33f2f7566f5ff08763bf5ada158f97c87fc240d1dcb04aa2a7b289018e33e",
                hex::decode("e715d5dc3bd8edecb453c59f85998591d7c14fd08057a0605cb416f6751eaad9")
                    .unwrap(),
            ),
            (
                "46e60abc3acbff858e382783f0739a8b2f2ba4c51b26941d979e60cb5292f11df1112b7016c0",
                hex::decode("359eee8d1ef18ed647bbd63cb4b2be85061f8e3fd67318e13924ddbc1beb815f")
                    .unwrap(),
            ),
            (
                "015b4b0759b0adee6c01de051bdacefe1f30eb571c83fa6c37607008696a9fa7f85273061e72",
                hex::decode("cf5cd07f31ca3aa3b7d2947da7e92c42ec5f981eff80ff1b438e59fd456465fb")
                    .unwrap(),
            ),
            (
                "7435604655772ca5ff011127c83692e40945187954da3bc7c01102d59701c7351aadbdc9ac8b",
                hex::decode("7f6a73aeb6de28f1d3935941caa8cab286d13d8c74f2352b5b717c3d743db9c1")
                    .unwrap(),
            ),
            (
                "c554d56a2eaffd8426006fb6d987cc615fb4ec05b1b15e793ab9d9127d79cf323787817467e6",
                hex::decode("14b98855c4f22295fcf3e2ec5d5fdfbb877979639c963bf6e226a0fb71902baf")
                    .unwrap(),
            ),
            (
                "c4850dbcddb9dfac6f44007ec58fe824bc58e3de2432de478f3e53f7965c2afd7ea651b6c2bf",
                hex::decode("6f5c23f8797f93d3d3c689fe1a3f5d9a1fbf326a7a6ea51fecbeaa9aba46f180")
                    .unwrap(),
            ),
            (
                "6a8f4f1d5a7405aa24cb1fb2a3c1dcaae74175c712002627289b5cd9dd887088afe605460abd",
                hex::decode("45f12760f6005a93cece248f5ec78adf15f9d29dafe397c8c28fefc72781d6fb")
                    .unwrap(),
            ),
            (
                "e464b9b1c9282d8edeed5832b95405761db6dacf6a156fc9119a396bdc8f8892815c7dce20fd",
                hex::decode("1c12d17a2a8b2c25950872f312d5d0758f07d8357c98897fc472565a44b3d1f1")
                    .unwrap(),
            ),
            (
                "9ae839af434aa13de6e8baa280541716811dcbaa33165fea5e9bad0c33998c10f16fcac4f214",
                hex::decode("686d28bf7e4b4cadf759994caed1e52092e12c11cef257a265b50402dbd70c3b")
                    .unwrap(),
            ),
            (
                "e92722d80103af9574f19a6cf72aab424335927eb7da022455f53314e3587dc8ece40d254981",
                hex::decode("b2e9ddef40897219a997ae7af277a5550cc10c54e793b6d2146de94df3bd552b")
                    .unwrap(),
            ),
            (
                "e2a02510f242f35e46b8840d8da42c087ea906b09d8e454c734663650236977da0362dd2ab43",
                hex::decode("4f756e475a706cdcec8eb1c02b21a591e0c0450cc0408ae8aec82ae97f634ecf")
                    .unwrap(),
            ),
            (
                "8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0",
                hex::decode("cd46b523d2ee92f205a00726d8544094bb4fe58142ecffd20ea32b37b6e6bfc3")
                    .unwrap(),
            ),
        ];

        for (expected_str, public_key) in test_cases {
            let expected = Address::parse_string(expected_str).unwrap();

            let public_key = PublicKey::new(public_key.as_slice().try_into().unwrap());
            let addr = UnlockConditions::standard_unlock_conditions(public_key).address();

            assert_eq!(addr, expected);
            // test string round-trip
            if !expected_str.starts_with("") {
                assert_eq!(addr.to_string(), "".to_string() + expected_str)
            } else {
                assert_eq!(addr.to_string(), expected_str)
            }
        }
    }

    #[test]
    fn test_seed_standard_unlock_hash() {
        const PHRASE: &str =
            "song renew capable taxi follow sword more hybrid laptop dance unfair poem";
        let test_addresses = vec![
            (
                0,
                Address::parse_string(
                    "16e09f8dc8a100a03ba1f9503e4035661738d1bea0b6cdc9bb012d3cd25edaacfd780909e550",
                )
                .unwrap(),
            ),
            (
                1,
                Address::parse_string(
                    "cb016a7018485325fa299bc247113e3792dbea27ee08d2bb57a16cb0804fa449d3a91ee647a1",
                )
                .unwrap(),
            ),
            (
                2,
                Address::parse_string(
                    "5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9e758b4f79b34",
                )
                .unwrap(),
            ),
            (
                3,
                Address::parse_string(
                    "c3bc7bc1431460ed2556874cb63714760120125da758ebbd78198534cb3d25774352fdbb3e8b",
                )
                .unwrap(),
            ),
            (
                4,
                Address::parse_string(
                    "ebc7eae02ecf76e3ba7312bab6b6f71e9d255801a3a3b83f7cc26bd520b2c27a511cd8604e4b",
                )
                .unwrap(),
            ),
            (
                5,
                Address::parse_string(
                    "fce241a44b944b10f414782dd35f5d96b92aec3d6da92a45ae44b7dc8cfb4b4ba97a34ce7032",
                )
                .unwrap(),
            ),
            (
                6,
                Address::parse_string(
                    "36d253e7c3af2213eccaf0a61c6d24be8668f72af6e773463f3c41efc8bb70f2b353b90de9dd",
                )
                .unwrap(),
            ),
            (
                7,
                Address::parse_string(
                    "c8f85375fb264428c86594863440f856db1da4614d75f4a30e3d9db3dfc88af6995128c6a845",
                )
                .unwrap(),
            ),
            (
                8,
                Address::parse_string(
                    "85ef2ba14ee464060570b16bddaac91353961e7545067ccdf868a0ece305f00d2c08ec6844c6",
                )
                .unwrap(),
            ),
            (
                9,
                Address::parse_string(
                    "9dcf644245eba91e7ea70c47ccadf479e6834c1c1221335e7246e0a6bc40e18362c4faa760b8",
                )
                .unwrap(),
            ),
            (
                4294967295,
                Address::parse_string(
                    "a906891f0c524fd272a905aa5dd7018c69e5d68222385cbd9d5292f38f021ce4bf00953a0659",
                )
                .unwrap(),
            ),
            (
                4294967296,
                Address::parse_string(
                    "b6ab338e624a304add7afe205361ac71821b87559a3b9c5b3735eaafa914eed533613a0af7fa",
                )
                .unwrap(),
            ),
            (
                18446744073709551615,
                Address::parse_string(
                    "832d0e8b5f967677d812d75559c373d930ad16eb90c31c29982a190bb7db9edf9438fd827938",
                )
                .unwrap(),
            ),
        ];

        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        for (i, expected) in test_addresses {
            let pk = seed.private_key(i).public_key();
            let addr: Address = UnlockConditions::standard_unlock_conditions(pk).address();

            assert_eq!(addr, expected, "index {}", i);
        }
    }
}
