// Calculate the rounded buffer size
pub fn integral_buffer_size(size: u32) -> u32 {
    // Calculate
    if (size % 4) == 0 {
        size / 4
    } else {
        (size / 4) + 1 // Add one for safety
    }
}

// Reads a bit-len int from the buffer
pub fn read_bit_len_int(buffer: &[u8], mut bit_index: u32, num_bits: u32) -> i64 {
    let mut data: i64 = 0;
    let mut wei: i64 = 1;

    for _ in 0..num_bits {
        let byte_index = (bit_index / 8) as usize;
        let bit_offset = (bit_index % 8) as u8;

        if ((buffer[byte_index] >> bit_offset) & 1) != 0 {
            data += wei;
        }

        bit_index += 1;
        wei *= 2;
    }

    data
}

// Reads a bit-len uint from the buffer
pub fn read_bit_len_uint(buffer: &[u8], mut bit_index: u32, num_bits: u32) -> u64 {
    let mut data: u64 = 0;
    let mut wei: u64 = 1;

    for _ in 0..num_bits {
        let byte_index = (bit_index / 8) as usize;
        let bit_offset = (bit_index % 8) as u8;

        if ((buffer[byte_index] >> bit_offset) & 1) != 0 {
            data += wei;
        }

        bit_index += 1;
        wei *= 2;
    }

    data
}
