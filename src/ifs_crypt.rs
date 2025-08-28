use crate::hash;
use wow_mpq::crypto::ENCRYPTION_TABLE;

const MPQ_HASH_KEY2_MIX: usize = 0x400;

/// Calculate BET table hash for a filename using Jenkins hashlittle2
pub fn bet_hash(filename: &str, hash_bits: u32) -> u64 {
    // Normalize filename: lowercase and convert / to \
    let normalized = filename.to_lowercase().replace('/', "\\").into_bytes();

    // Initial seeds
    let mut primary: u32 = 1;
    let mut secondary: u32 = 2;

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

/// Decrypt a block of data
/// We don't handle remaining bytes if not aligned to 4, just leave them as-is
pub fn decrypt_block(data: &mut [u32], mut size: u32, mut key: u32) -> u32 {
    // Round to DWORDs
    size = size >> 2; // size / 4

    let mut seed: u32 = 0xEEEEEEEE;

    if size != 0 {
        for idx in 0..size {
            // Get the current DWORD
            let value = data.get_mut(idx as usize).unwrap();

            // Update seed using the encryption table and key
            seed = seed.wrapping_add(ENCRYPTION_TABLE[MPQ_HASH_KEY2_MIX + (key & 0xFF) as usize]);

            // Decrypt the current DWORD
            let ch = *value ^ (key.wrapping_add(seed));
            *value = ch;

            // Update key for next round
            key = (!key << 21).wrapping_add(0x11111111) | (key >> 11);

            // Update seed for next round
            seed = ch
                .wrapping_add(seed)
                .wrapping_add(seed << 5) // seed * 32
                .wrapping_add(3);
        }
    }

    seed
}

/// Decrypt file data in-place
/// We don't handle remaining bytes if not aligned to 4, just leave them as-is
pub fn decrypt_file_data(data: &mut [u8], key: u32) {
    if data.is_empty() || key == 0 {
        return;
    }

    // Process full u32 chunks
    let chunks = data.len() / 4;
    if chunks > 0 {
        // Create a properly aligned u32 slice
        let mut u32_data = Vec::with_capacity(chunks);

        // Copy data as u32 values (little-endian)
        for i in 0..chunks {
            let offset = i * 4;
            let value = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            u32_data.push(value);
        }

        // Decrypt the u32 data
        wow_mpq::crypto::decrypt_block(&mut u32_data, key);

        // Copy back to byte array
        for (i, &value) in u32_data.iter().enumerate() {
            let offset = i * 4;
            let bytes = value.to_le_bytes();
            data[offset] = bytes[0];
            data[offset + 1] = bytes[1];
            data[offset + 2] = bytes[2];
            data[offset + 3] = bytes[3];
        }
    }
}
