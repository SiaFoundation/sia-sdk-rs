use blake2::Blake2b;
use blake2::digest::consts::U32;

pub use blake2::digest::Digest;
pub type Output = blake2::digest::Output<Blake2b256>;
pub type Blake2b256 = Blake2b<U32>;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_blake2b256() {
        let mut hasher = Blake2b256::new();
        hasher.update(b"hello, world!");
        let result = hasher.finalize();
        let expected =
            hex::decode("480a927c7e3f9430f03141250f1def67380fec3943accb4575e568750a103638")
                .unwrap();
        assert_eq!(result.to_vec(), expected);
    }
}
