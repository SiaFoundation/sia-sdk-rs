use crate::signing::PrivateKey;
use crate::types::Hash256;
use bip39::{Error as MnemonicError, Language, Mnemonic};
use blake2b_simd::Params;

pub struct Seed([u8; 16]);

#[derive(Debug, PartialEq)]
pub enum SeedError {
    MnemonicError,
    InvalidLength,
}

impl From<MnemonicError> for SeedError {
    fn from(_: MnemonicError) -> Self {
        SeedError::MnemonicError
    }
}

impl Seed {
    pub fn new(seed: [u8; 16]) -> Self {
        Self(seed)
    }

    pub fn from_mnemonic(s: &str) -> Result<Self, SeedError> {
        let m = Mnemonic::parse_in(Language::English, s)?;
        let buf = m.to_entropy();
        if buf.len() != 16 {
            return Err(SeedError::InvalidLength);
        }

        let mut entropy = [0; 16];
        entropy.copy_from_slice(&buf[..16]);
        Ok(Self::new(entropy))
    }

    pub fn to_mnemonic(&self) -> String {
        Mnemonic::from_entropy_in(Language::English, &self.0)
            .unwrap()
            .to_string()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Derive a private key from the seed
    pub fn private_key(&self, index: u64) -> PrivateKey {
        let mut params = Params::new();
        params.hash_length(32);

        let entropy: Hash256 = params.to_state().update(self.0.as_ref()).finalize().into();

        let seed: Hash256 = params
            .to_state()
            .update(entropy.as_ref())
            .update(&index.to_le_bytes())
            .finalize()
            .into();

        seed.into()
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        // Zero out the private key
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_from_entropy() {
        let test_cases = vec![
			([23,154,249,239,129,81,216,147,144,163,207,136,238,88,11,253],"bleak style know actor budget endorse dream ketchup material index actual wide"),
			([125,190,141,81,70,235,204,217,162,19,65,96,237,125,157,255],"laundry virtual february miss rubber holiday marriage habit genius hip guess yard"),
			([56,47,30,87,122,143,19,221,189,249,105,45,161,38,172,91],"deal jump noise vital van uphold wave coffee color ankle prison repeat"),
			([68,205,7,92,32,16,228,222,144,102,94,12,179,15,67,251],"dynamic habit strike dizzy atom hungry dose slim arrow observe special wash"),
			([113,45,77,233,42,222,26,5,158,171,102,114,10,7,178,19],"illness heavy kid fiber ticket actress kingdom holiday improve expand uncle chest"),
			([189,194,141,142,240,157,147,143,61,104,167,223,33,191,95,226],"saddle behave glove thrive summer shy volcano belt tennis assume subject series"),
			([156,21,48,230,15,181,230,46,105,106,91,163,205,77,45,150],"orchard praise define buyer fury blame pizza enter phrase heavy enter collect"),
			([14,38,59,189,192,248,53,60,139,36,93,58,42,156,174,238],"athlete crack urge limit local oxygen clutch merry demand female close talent"),
			([141,252,20,155,232,12,56,225,252,11,92,219,9,189,23,179],"mistake thing cheap source seminar ill usual high swallow evil echo grid"),
			([25,192,89,200,149,97,136,115,38,103,19,229,88,165,62,169],"border actress impulse client blush define office tiny torch share exile famous"),
			([255,43,106,70,38,84,73,72,184,0,154,228,158,156,171,32],"you forget muscle erosion duty picture theme battle tonight visual client double"),
			([222,237,244,22,242,80,27,122,27,91,110,101,44,200,107,151],"ten hurry aisle tool accuse rug hope horse gown green brain comfort"),
			([96,74,173,157,208,13,130,1,168,248,254,178,92,220,59,233],"gate fever guess parade subway absorb physical cabin rather tragic auction spread"),
			([176,115,232,168,178,206,187,177,117,105,82,1,211,62,184,132],"race palm clay grain two suffer stick clean achieve okay purchase anger"),
			([162,226,161,55,247,115,251,40,6,205,151,77,203,35,63,198],"pepper bench evil upon distance neglect brass real evidence flip soup mind"),
			([199,68,177,121,94,197,135,255,140,56,181,119,99,179,124,65],"shrug cereal furnace rural flash zone couch birth jazz budget tenant lock"),
			([149,139,33,29,170,228,57,90,209,219,67,202,162,198,242,138],"night flip electric fiction drum pulp electric half skirt bike royal benefit"),
			([32,138,79,90,166,241,239,197,108,63,107,211,140,3,80,129],"calm fame stove evil bus tired rail uniform squeeze gas stage acoustic"),
			([231,198,66,33,240,199,105,69,236,87,87,250,128,220,227,145],"treat craft mask thunder isolate pepper rally turtle whisper alone decline card"),
			([130,4,98,53,124,85,66,215,112,229,188,157,95,195,49,201],"link cart minute weather feature hill seminar resource outer wrap small narrow"),
			([228,84,238,177,92,231,129,253,139,4,83,68,252,160,139,22],"tone polar proof right job yard clown media eager topic carpet cluster"),
			([227,39,94,239,75,67,63,122,188,27,58,162,126,135,55,250],"tobacco depend rookie notable crop run vacant guard pen vintage social visual"),
			([228,96,128,106,248,223,176,232,179,247,6,219,81,173,27,141],"tongue advice boy vast wild inmate sound this swap miracle eight bottom"),
			([204,38,228,251,95,106,131,62,103,254,162,86,97,48,254,222],"slow damp disagree salute popular palace paper stairs filter another distance sadness"),
		];

        for (entropy, expected) in test_cases {
            let seed = Seed::new(entropy);
            assert_eq!(seed.to_mnemonic(), expected);
        }
    }

    #[test]
    fn test_seed_private_key() {
        const PHRASE: &str =
            "wealth salon venue abstract blossom hollow south over accuse bunker guide saddle";
        let test_addresses = vec![
			(0, hex::decode("e313a1aa2dbe411b5335ced5592e87cb002f47a874e27e9cb90eab285c675e366d29b52b7b312fb5e4f657afd0105d3d6dcc5c326131a033597501d25612789f").unwrap()),
			(1, hex::decode("0a909bf1d36c876cb776b81e19c8b4a1351c644e329db3be07f6dfce59b75f4d3fa53cfea6763b07cc4202a0ba36574d99fa6ca3f807dbff2f2266c4d0a0a76d").unwrap()),
			(2, hex::decode("866b40a6ee117ab8e65ee0772ca4e463e98edbf0793beae08a784745e7f10554294324450371bb263bc02c4536a04afa355ca490ef6481fd682dfd44bdb0f464").unwrap()),
			(3, hex::decode("f713e2a9cc2415d7069d136c73dd3a67c5f2a63cc04f1106b980d6d6cd816f6bf710d69b256ae23f4b28d1f02f714fed04ea2c9268598835713eec36697bf179").unwrap()),
			(4, hex::decode("433b5bf2c3ec44895af7299148ba38deaa7324c5146821fcef407708abc211bcb12b2a480977ffdc4c3801752b0e2bee06219311b7bdce80189be961f47d7ac9").unwrap()),
			(5, hex::decode("48a4765ece4d7e6b12f4f8b20caaca4b2249654ada2b9d0d31d855517244b1ed8850f06b52e7ce6b5ea061ac6b69f3febb3fc96e58c590c975300fb20f317dcc").unwrap()),
			(6, hex::decode("2de36d94f299ab39511e9eb3fe0cf5cc989b25e2943ca9c3a87ac592831791d76b0ee63d4be3b5296fe3961150b6bc3dd5f0acc56235fb8a62143a7eb73bdaa7").unwrap()),
			(7, hex::decode("ecbd64189b9429583ad62173035cf3680238e5d90727220f55d466e88dc631b70299cbd2b777df0e62099f3f5f913692d022a3faabd461a2933754ec3aa35c21").unwrap()),
			(8, hex::decode("5e836458fccb204dfe0e300c66ca2c47ad7efe9f835cda99d1a3cf22cf642634d53903b6ba22cf84adcae25f3d27d90323017ff793115b559df26fc0a4450cf4").unwrap()),
			(9, hex::decode("9abd3e40d6d3b10d36966cec65861d7f08c6aa7f2d2845b0e9f10e15cc9e9f28eb63b79a7719c1a8323fe2d3da06d121ccbda1342d9f0913860f5e0817af1390").unwrap()),
			(4294967295, hex::decode("71945cbc310c189f01fe8727a0060c007528aa0fd4812e4c5c7aa8b0e518906fc7dcf5e7623152e310ed440b8abf02e02fbead45553f13b3e8a7bea78a16d1b8").unwrap()),
			(4294967296, hex::decode("41602321666c7ba93b05729208897ddf89940afdf02c38ebbd88f0a4906839232cd126afb5ccaef91ab77fcc27d076d94c5d152729bde3794bcd03226679889c").unwrap()),
			(18446744073709551615, hex::decode("c03b2570cb69e300cd4ccbe0c4d8ee7b8ccfad7383f10aa2df52a4a9d05ab843d39fbd56458e94d711061748a051d434d2200e1af71df56070d2df0883453b2c").unwrap()),
		];

        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        for (i, expected) in test_addresses {
            let pk = seed.private_key(i);
            assert_eq!(pk.as_bytes(), expected, "index {i}");
        }
    }

    #[test]
    fn test_seed_public_key() {
        const PHRASE: &str =
            "wealth salon venue abstract blossom hollow south over accuse bunker guide saddle";
        let test_addresses = vec![
			(0, hex::decode("e313a1aa2dbe411b5335ced5592e87cb002f47a874e27e9cb90eab285c675e366d29b52b7b312fb5e4f657afd0105d3d6dcc5c326131a033597501d25612789f").unwrap()),
			(1, hex::decode("0a909bf1d36c876cb776b81e19c8b4a1351c644e329db3be07f6dfce59b75f4d3fa53cfea6763b07cc4202a0ba36574d99fa6ca3f807dbff2f2266c4d0a0a76d").unwrap()),
			(2, hex::decode("866b40a6ee117ab8e65ee0772ca4e463e98edbf0793beae08a784745e7f10554294324450371bb263bc02c4536a04afa355ca490ef6481fd682dfd44bdb0f464").unwrap()),
			(3, hex::decode("f713e2a9cc2415d7069d136c73dd3a67c5f2a63cc04f1106b980d6d6cd816f6bf710d69b256ae23f4b28d1f02f714fed04ea2c9268598835713eec36697bf179").unwrap()),
			(4, hex::decode("433b5bf2c3ec44895af7299148ba38deaa7324c5146821fcef407708abc211bcb12b2a480977ffdc4c3801752b0e2bee06219311b7bdce80189be961f47d7ac9").unwrap()),
			(5, hex::decode("48a4765ece4d7e6b12f4f8b20caaca4b2249654ada2b9d0d31d855517244b1ed8850f06b52e7ce6b5ea061ac6b69f3febb3fc96e58c590c975300fb20f317dcc").unwrap()),
			(6, hex::decode("2de36d94f299ab39511e9eb3fe0cf5cc989b25e2943ca9c3a87ac592831791d76b0ee63d4be3b5296fe3961150b6bc3dd5f0acc56235fb8a62143a7eb73bdaa7").unwrap()),
			(7, hex::decode("ecbd64189b9429583ad62173035cf3680238e5d90727220f55d466e88dc631b70299cbd2b777df0e62099f3f5f913692d022a3faabd461a2933754ec3aa35c21").unwrap()),
			(8, hex::decode("5e836458fccb204dfe0e300c66ca2c47ad7efe9f835cda99d1a3cf22cf642634d53903b6ba22cf84adcae25f3d27d90323017ff793115b559df26fc0a4450cf4").unwrap()),
			(9, hex::decode("9abd3e40d6d3b10d36966cec65861d7f08c6aa7f2d2845b0e9f10e15cc9e9f28eb63b79a7719c1a8323fe2d3da06d121ccbda1342d9f0913860f5e0817af1390").unwrap()),
			(4294967295, hex::decode("71945cbc310c189f01fe8727a0060c007528aa0fd4812e4c5c7aa8b0e518906fc7dcf5e7623152e310ed440b8abf02e02fbead45553f13b3e8a7bea78a16d1b8").unwrap()),
			(4294967296, hex::decode("41602321666c7ba93b05729208897ddf89940afdf02c38ebbd88f0a4906839232cd126afb5ccaef91ab77fcc27d076d94c5d152729bde3794bcd03226679889c").unwrap()),
			(18446744073709551615, hex::decode("c03b2570cb69e300cd4ccbe0c4d8ee7b8ccfad7383f10aa2df52a4a9d05ab843d39fbd56458e94d711061748a051d434d2200e1af71df56070d2df0883453b2c").unwrap()),
		];

        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        for (i, expected) in test_addresses {
            let pk = seed.private_key(i).public_key();
            assert_eq!(pk.as_ref(), expected[32..].as_ref(), "index {i}");
        }
    }
}
