use crate::hash;

pub struct IFSCrypt {}

impl IFSCrypt {
    /// Note: Copied and modified from wow-mpq lib for bet file hash use
    ///
    /// Calculate HET table hash for a filename using Jenkins hashlittle2
    ///
    /// This function normalizes the filename and applies Jenkins hashlittle2
    /// to generate the hash value used in HET tables.
    pub fn bet_hash(filename: &str, hash_bits: u32) -> u64 {
        // Normalize filename: lowercase and convert / to \
        let normalized = filename
            .bytes()
            .map(|b| {
                let b = if b == b'/' { b'\\' } else { b };
                // Simple ASCII lowercase
                if b.is_ascii_uppercase() { b + 32 } else { b }
            })
            .collect::<Vec<u8>>();

        // Initial seeds
        let mut primary = 1u32;
        let mut secondary = 2u32;

        // Apply hashlittle2
        hash::hashlittle2(&normalized, &mut secondary, &mut primary);

        // Combine into 64-bit hash
        let full_hash = ((primary as u64) << 32) | (secondary as u64);

        // Calculate masks
        let or_mask = 1u64 << (hash_bits - 1);

        let and_mask: u64 = if hash_bits != 64 {
            (1u64 << hash_bits) - 1
        } else {
            0xFFFFFFFFFFFFFFFF
        };

        // Apply masks
        let file_name_hash = (full_hash & and_mask) | or_mask;

        // Shift it to get the bet hash

        file_name_hash & (and_mask >> 8)
    }
}
