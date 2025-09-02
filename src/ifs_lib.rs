use crate::array_read_ext::ArrayReadExt;
use crate::hash::HashCRC32;
use crate::hash_xxh64::HashXXH64;
use crate::ifs_structs::{
    FileIV, IFSBetHeader, IFSBetTable, IFSFileEntry, IFSFileFlags, IFSHeader, IFSHetHeader,
    IFSHetTable, IVPartLength,
};
use crate::io_ext::SeekReadExt;
use crate::struct_read_ext::StructReadExt;
use crate::{ifs_crypt, utils};
use aes::Aes192;
use ctr::{
    Ctr128BE,
    cipher::{KeyIvInit, StreamCipher},
};
use flate2::read::ZlibDecoder;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::error::Error;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use walkdir::WalkDir;
use wow_mpq::{
    crypto::{hash_string, hash_type},
    decompress, decrypt_block,
};

#[cfg(test)]
use std::io::Write;

// A class that handles reading from IFS packages
#[derive(Debug, Default, Clone)]
pub struct IFSLib {
    // A list of loaded file entries
    pub file_entries: HashMap<u64, IFSFileEntry>,
    // A list of loaded IFS package paths
    pub package_paths: Vec<String>,
}

impl IFSLib {
    pub fn new() -> Self {
        Self::default()
    }

    // Generate a cipher for AES-CTR (AES192)
    fn generate_cipher(aes_iv: &[u8; 16]) -> Ctr128BE<Aes192> {
        // The AES key
        static AES_KEY: [u8; 24] = [
            0x15, 0x9a, 0x03, 0x25, 0xe0, 0x75, 0x2e, 0x80, 0xc6, 0xc0, 0x94, 0x2a, 0x50, 0x5c,
            0x1c, 0x68, 0x8c, 0x17, 0xef, 0x53, 0x99, 0xf8, 0x68, 0x3c,
        ];

        // Generate cipher
        Ctr128BE::<Aes192>::new_from_slices(&AES_KEY, aes_iv).expect("Invalid key or IV length")
    }

    // Load packages from a directory
    pub fn load_packages(&mut self, iips_dir: &Path) -> Result<(), Box<dyn Error>> {
        // TODO:
        for entry in WalkDir::new(iips_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if entry.file_type().is_file() && path.extension().unwrap().eq("ifs") {
                #[cfg(test)]
                println!("Loading {:?}", path);

                self.load_package(path)?;
            }
        }

        Ok(())
    }

    // Load a package
    pub fn load_package(&mut self, file_path: &Path) -> Result<(), Box<dyn Error>> {
        let mut file = File::open(file_path)?;

        // Read the header
        let header: IFSHeader = file.read_struct()?;

        // Verify magic
        // TODO: Use error result to check function and handle it by `?`
        if !header.verify_magic() {
            let magic = header.magic; // aligned for formatting
            let msg = format!("Invalid IFS file magic: expected 0x7366696E, got {magic:#x}");

            return Err(msg.into());
        }

        // Calculate table hashes
        let het_key = hash_string("(hash table)", hash_type::FILE_KEY);
        let bet_key = hash_string("(block table)", hash_type::FILE_KEY);
        let mut lst_hash: Option<u64> = None;

        // Add the package to the cache
        self.package_paths.push(file_path.display().to_string());
        // Get index
        let package_index = self.package_paths.len() - 1;

        // Begin HetTable parse -------------------------------------------
        // HetTable header
        let het_header: IFSHetHeader = file.read_struct_at(header.het_table_pos)?;

        // Read the data
        let het_safe_size = utils::integral_buffer_size(het_header.data_size) as usize;
        let mut het_buffer = file.read_array::<u32>(het_safe_size)?;

        // Decrypt the data
        decrypt_block(&mut het_buffer, het_key);

        // Read the required het table information
        let het_buffer_u8: Vec<u8> = het_buffer.iter().flat_map(|v| v.to_le_bytes()).collect();
        let mut het_buffer_reader = Cursor::new(het_buffer_u8);
        // Read het table
        let het_table: IFSHetTable = het_buffer_reader.read_struct()?;

        // End --------------------------------------------------------------

        // Begin BetTable parse -------------------------------------------

        // Read the bet header
        let bet_header: IFSBetHeader = file.read_struct_at(header.bet_table_pos)?;

        // Read the data
        let bet_safe_size = utils::integral_buffer_size(bet_header.data_size) as usize;
        let mut bet_buffer = file.read_array::<u32>(bet_safe_size)?;

        // Decrypt the data
        decrypt_block(&mut bet_buffer, bet_key);

        // Read the required bet table information
        let bet_buffer_u8: Vec<u8> = bet_buffer.iter().flat_map(|v| v.to_le_bytes()).collect();
        let mut bet_buffer_reader = Cursor::new(bet_buffer_u8);

        // Read bet table
        let bet_table: IFSBetTable = bet_buffer_reader.read_struct()?;

        // Tables size
        let table_entries_size = (bet_table.table_entry_size * bet_table.entry_count).div_ceil(8);
        let table_hashes_size = (bet_table.hash_size_total * bet_table.entry_count).div_ceil(8);

        // Read the tables
        let table_entries = bet_buffer_reader.read_array::<u8>(table_entries_size as usize)?;
        let table_hashes = bet_buffer_reader.read_array::<u8>(table_hashes_size as usize)?;

        // A list of file entries
        let mut file_entries = HashMap::new();

        // Offsets
        let mut bit_offset = 0;
        let mut hash_offset = 0;

        // Parse and read each entry
        // TODO: Can use bit offset to load info
        for _ in 0..bet_table.entry_count {
            // New entry, set index
            let mut entry = IFSFileEntry {
                file_package_index: package_index,
                ..Default::default()
            };

            // Read data
            entry.file_position =
                utils::read_bit_len_int(&table_entries, bit_offset, bet_table.bit_count_file_pos)
                    as usize;
            bit_offset += bet_table.bit_count_file_pos;

            entry.file_size =
                utils::read_bit_len_int(&table_entries, bit_offset, bet_table.bit_count_file_size)
                    as usize;
            bit_offset += bet_table.bit_count_file_size;

            entry.compressed_size =
                utils::read_bit_len_int(&table_entries, bit_offset, bet_table.bit_count_cmp_size)
                    as usize;
            bit_offset += bet_table.bit_count_cmp_size;

            let flags =
                utils::read_bit_len_int(&table_entries, bit_offset, bet_table.bit_count_flag_size);
            entry.flags = IFSFileFlags::from_bits(flags as u32).unwrap();
            bit_offset += bet_table.bit_count_flag_size;

            // Skip over unknown data
            bit_offset += bet_table.bit_count_hash_size;
            bit_offset += bet_table.hash_array_size;

            // Grab the hash and use as the key
            let name_hash =
                utils::read_bit_len_uint(&table_hashes, hash_offset, bet_table.hash_size_total);
            hash_offset += bet_table.hash_size_total;

            // Skip the folders or invalid entries
            if entry.file_size == 0 || !entry.flags.exists() {
                continue;
            }

            // Add it
            file_entries.insert(name_hash, entry);
        }

        // End --------------------------------------------------------------

        // Find the list file hash
        for (&hash, _) in &file_entries {
            if hash & 0xFFFFFFFF == 0xB2F3866A {
                lst_hash = Some(hash);
            }
        }

        if lst_hash.is_none() {
            return Err("list file hash not found".into());
        }

        // Get the list file for the names of file entries
        let lst_file = file_entries
            .get(&lst_hash.unwrap())
            .ok_or("list file not found")?;

        let lst_data = self.read_list_file(&mut file, lst_file, &header)?;

        // To string
        let lst_content =
            String::from_utf8(lst_data).map_err(|e| format!("Invalid UTF-8 in list file: {e}"))?;

        // Find the lst file
        let mut hashes: Option<HashMap<u64, String>> = None;
        for line in lst_content.lines().map(str::trim) {
            if !line.is_empty() && line.ends_with(".lst") {
                hashes = Some(HashMap::new());

                // Calculate BET hash
                let lst_hash = ifs_crypt::bet_hash(line, het_table.hash_entry_size);

                // Get the lst file for the names with original case of file entries
                let lst_file = file_entries.get(&lst_hash).ok_or("lst file not found")?;

                // Read the lst file
                let lst_data = self.read_list_file(&mut file, lst_file, &header)?;

                // To string
                let lst_content = String::from_utf8(lst_data)
                    .map_err(|e| format!("Invalid UTF-8 in lst file: {e}"))?;

                // Split by line, trim the line and check for valid entries
                for line in lst_content.lines().map(str::trim) {
                    // Skip empty lines
                    if line.is_empty() {
                        continue;
                    }

                    // Calculate BET hash
                    let bet_file_hash = ifs_crypt::bet_hash(line, het_table.hash_entry_size);

                    hashes
                        .as_mut()
                        .unwrap()
                        .insert(bet_file_hash, line.to_string());
                }

                break;
            }
        }

        // Split by line, trim the line and check for valid entries
        for line in lst_content.lines().map(str::trim) {
            // Skip empty lines
            if line.is_empty() {
                continue;
            }

            // Calculate BET hash
            let bet_file_hash = ifs_crypt::bet_hash(line, het_table.hash_entry_size);

            // Check if the entries exist by matching the hashes with names from the list file
            if let Some(entry) = file_entries.get_mut(&bet_file_hash) {
                // Set the path for the entry
                if let Some(hashes) = hashes.as_ref() {
                    // Use original case names if available
                    if hashes.contains_key(&bet_file_hash) {
                        entry.file_path = hashes.get(&bet_file_hash).unwrap().clone();
                    } else {
                        // No original case names available, should not happen
                        return Err(
                            format!("Original case name not found for entry: {}", line).into()
                        );
                    }
                } else {
                    // No original case names available, use lower case
                    // Some IFS packages don't have a lst file
                    entry.file_path = line.to_string();
                }

                // Calculate XXHash for quick lookup later
                let entry_hash = line.hash_xxh64();

                // Add the new file
                match self.file_entries.entry(entry_hash) {
                    Entry::Vacant(v) => {
                        v.insert(entry.to_owned());

                        // #[cfg(test)]
                        // println!("Added entry: {}", entry.file_path);
                    }
                    Entry::Occupied(mut o) => {
                        /*let mut msg = format!(
                            "Warning: Duplicate overwriting: '{}'",
                            entry.path
                        );

                        let existing_size = o.get().file_size;
                        let new_size = entry.file_size;
                        if existing_size != new_size {
                            msg = format!(
                                "{msg}. Size: {existing_size} -> {new_size}"
                            );
                        }

                        #[cfg(test)]
                        println!("{}", msg);*/

                        o.insert(entry.to_owned());
                    }
                }
            }
        }

        Ok(())
    }

    pub fn read_list_file(
        &self,
        ifs_file: &mut File,
        lst_entry: &IFSFileEntry,
        ifs_header: &IFSHeader,
    ) -> io::Result<Vec<u8>> {
        // Read the data
        let lst_cmp_size = lst_entry.compressed_size;
        let mut lst_buffer =
            ifs_file.read_array_at::<u8>(lst_entry.file_position as u64, lst_cmp_size)?;

        #[cfg(test)]
        {
            let mut f = File::create("listfile_raw.bin")?;
            f.write_all(&lst_buffer)?;
            f.flush()?;
        }

        let encrypted = lst_entry.flags.is_encrypted();
        let compressed = lst_entry.flags.is_compressed();

        // Return raw data if not encrypted or compressed
        if !encrypted && !compressed {
            return Ok(lst_buffer);
        }

        // Get the hash key for the list file
        let lst_key: Option<u32> = if encrypted {
            let key = hash_string("(listfile)", hash_type::FILE_KEY);
            assert_eq!(key, 0x2D2F0A94);

            Some(key)
        } else {
            None
        };

        if !compressed || lst_entry.flags.is_single_unit() {
            // Decrypt full data and return directly
            ifs_crypt::decrypt_file_data(&mut lst_buffer, lst_key.unwrap());

            #[cfg(test)]
            {
                let mut f = File::create("listfile_decrypted.bin")?;
                f.write_all(&lst_buffer)?;
                f.flush()?;
            }

            return Ok(lst_buffer);
        }

        // Get the sector info
        let max_sector_size = ifs_header.max_sector_size() as usize;
        let sector_count = (lst_entry.file_size + max_sector_size - 1) / max_sector_size;
        let sector_offset_count = sector_count + 1;
        let sector_offset_size = sector_offset_count * size_of::<u32>();

        // Decrypt the offsets
        if lst_entry.flags.is_encrypted() {
            ifs_crypt::decrypt_file_data(
                &mut lst_buffer[..sector_offset_size],
                lst_key.unwrap().wrapping_sub(1),
            );
        }

        // Read the offsets
        let mut lst_reader = Cursor::new(&mut lst_buffer);
        let offsets = lst_reader.read_array::<u32>(sector_offset_count)?;

        // #[cfg(test)]
        // let mut f_decmp = File::create("listfile_decompressed_temp.bin")?;

        // #[cfg(test)]
        // let mut f_decry = File::create("listfile_decrypted_temp.bin")?;

        let mut buf_uncomp: Vec<u8> = Vec::with_capacity(lst_entry.file_size);

        for i in 0..sector_count {
            let sector_start = offsets[i];
            let sector_end = offsets[i + 1];

            let comp_size = (sector_end - sector_start) as usize;
            let remaining = lst_entry.file_size - i * max_sector_size;
            let is_raw = comp_size >= remaining || comp_size == max_sector_size; // TODO:
            let uncmp_size = if is_raw {
                comp_size
            } else {
                std::cmp::min(max_sector_size, remaining)
            };

            #[cfg(test)]
            println!(
                "Processing sector {i}: raw_start={sector_start}, raw_end={sector_end}, is_raw={is_raw}, comp_size={comp_size}, uncmp_size={uncmp_size}",
            );

            let sector_buffer = &mut lst_buffer[sector_start as usize..sector_end as usize];

            if lst_entry.flags.is_encrypted() {
                ifs_crypt::decrypt_file_data(
                    sector_buffer,
                    lst_key.unwrap().wrapping_add(i as u32),
                );
            }

            // #[cfg(test)]
            // {
            //     f_decry.write_all(&sector_buffer)?;
            //     f_decry.flush()?;
            // }

            if is_raw {
                buf_uncomp.extend_from_slice(sector_buffer);

                #[cfg(test)]
                println!("Copied raw sector size: {}", uncmp_size);
            } else {
                let sector_buffer =
                    decompress(&sector_buffer[1..], sector_buffer[0], uncmp_size).unwrap();

                // #[cfg(test)]
                // {
                //     f_decmp.write_all(&sector_buffer)?;
                //     f_decmp.flush()?;
                // }

                buf_uncomp.extend(sector_buffer);

                #[cfg(test)]
                println!("Decompressed sector size: {}", uncmp_size);
            }
        }

        #[cfg(test)]
        {
            let mut f = File::create("listfile_decrypted.bin")?;
            f.write_all(&lst_buffer)?;
            f.flush()?;
        }

        #[cfg(test)]
        {
            let mut f = File::create("listfile_decompressed.bin")?;
            f.write_all(&buf_uncomp)?;
            f.flush()?;
        }

        Ok(buf_uncomp)
    }

    pub fn get_entry_hash(entry_path: &str) -> u64 {
        entry_path.hash_xxh64()
    }

    pub fn entry_exists_from_path(&self, entry_path: &str) -> bool {
        let entry_hash = Self::get_entry_hash(entry_path);
        self.file_entries.contains_key(&entry_hash)
    }

    pub fn try_get_entry(&self, entry_path: &str) -> io::Result<&IFSFileEntry> {
        let entry_hash = Self::get_entry_hash(entry_path);
        self.file_entries.get(&entry_hash).ok_or(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Entry not found: {}", entry_path),
        ))
    }

    // Read an entry from path
    pub fn read_entry_from_path(&self, file_path: &str) -> io::Result<Vec<u8>> {
        let entry = self.try_get_entry(file_path)?;
        self.read_entry(entry)
    }

    // Read an entry
    pub fn read_entry(&self, entry: &IFSFileEntry) -> io::Result<Vec<u8>> {
        // Get the file path
        let entry_path = &entry.file_path;

        // Open the package for reading
        let package_path = &self.package_paths[entry.file_package_index];
        let mut reader = File::open(package_path)?;

        // Read the data
        let entry_data =
            reader.read_array_at::<u8>(entry.file_position as u64, entry.compressed_size)?;

        // Some files are not encrypted or compressed, return directly
        // TODO: Any flags to check if encrypted?
        if entry_path.ends_with(".ff") || entry_path.ends_with(".lst") {
            return Ok(entry_data);
        };

        // The file data is encrypted
        let mut enc_data_reader = Cursor::new(&entry_data);

        // Calculate the packed size
        let packed_size = entry_data.len() - 4;

        // Read the unpacked size from the end of the file
        enc_data_reader.seek(SeekFrom::End(-4))?;
        let unpacked_size = enc_data_reader.read_struct::<u32>()? as usize;

        // Read the nonce for the IV
        let file_name = Path::new(entry_path).file_name().unwrap().to_str().unwrap();
        let nonce = file_name.hash_crc32(file_name.len() as u32);

        // Build the file IV
        let mut file_iv = FileIV {
            nonce,
            unpacked_size: unpacked_size as u32,
            iv_counter: Default::default(),
        };

        // The chunk size to decrypt at once
        const CRYPT_CHUNK_SIZE: usize = 0x8000;

        // Allocate the buffers
        let mut encrypted_buffer = vec![0u8; CRYPT_CHUNK_SIZE];
        let mut decrypted_buffer = vec![0u8; packed_size];
        let mut result_buffer = vec![0u8; unpacked_size];

        // The current offset in the packed data
        let mut packed_offset = 0;

        // Go back to start
        enc_data_reader.set_position(0);

        // Decrypt chunks
        while packed_offset < packed_size {
            // Calculate the block size
            let left = packed_size - packed_offset;
            let block_size = left.min(CRYPT_CHUNK_SIZE);

            // Update the IV counter
            file_iv.iv_counter = IVPartLength {
                iv_index: packed_offset as u32,
                iv_block_size: block_size as u32,
            };

            // Generate the cipher
            let mut cipher = Self::generate_cipher(&file_iv.to_bytes());

            // Read the chunk
            enc_data_reader.read_exact(&mut encrypted_buffer[..block_size])?;

            // Decrypt the buffer
            cipher
                .apply_keystream_b2b(
                    &encrypted_buffer[..block_size],
                    &mut decrypted_buffer[packed_offset..(packed_offset + block_size)],
                )
                .unwrap();

            // Advance
            packed_offset += block_size;
        }

        // Check if we have decrypted data
        if packed_offset == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "No data decrypted",
            ));
        }

        // Decompress
        {
            // Verify zlib header
            if decrypted_buffer[..2] != [0x78, 0xDA] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid zlib header",
                ));
            }

            // Decompress using zlib
            let mut decoder = ZlibDecoder::new(decrypted_buffer.as_slice());
            decoder.read_exact(&mut result_buffer)?;
        }

        Ok(result_buffer)
    }
}
