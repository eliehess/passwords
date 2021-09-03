pub mod hash {
    use sha2::{Sha256, Digest};
    
    pub fn hash(input: impl AsRef<[u8]>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input);
        return hasher
            .finalize()
            .into_iter()
            .map(|x| if x < 16 { format!("0{:x}", x) } else { format!("{:x}", x) })
            .collect();
    }
}