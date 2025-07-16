use crate::array_read_ext::ArrayReadExt;
use crate::hash::HashCRC32;
use crate::hash_xxh64::HashXXH64;
use crate::ifs_crypt::IFSCrypt;
use crate::ifs_structs::{
    FileIV, IFSBetHeader, IFSBetTable, IFSFileEntry, IFSHeader, IFSHetHeader, IFSHetTable,
    IVPartLength,
};
use crate::io_ext::SeekReadExt;
use crate::struct_read_ext::StructReadExt;
use crate::utils;
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
    decrypt_block,
};

// A class that handles reading from IFS packages
#[derive(Debug, Default, Clone)]
pub struct IFSLib {
    // A list of loaded IFS files
    pub ifs_files: HashMap<u64, IFSFileEntry>,
    // A list of loaded IFS file paths
    pub ifs_packages: Vec<String>,
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
                self.load_package(entry.path())?;
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
        if header.magic != 0x7366696E {
            let magic = header.magic;
            let msg = format!("Invalid IFS file magic: expected 0x7366696E, got {magic:#x}");

            return Err(msg.into());
        }

        // Calculate table hashes
        let het_key = hash_string("(hash table)", hash_type::FILE_KEY);
        let bet_key = hash_string("(block table)", hash_type::FILE_KEY);
        let mut list_file_hash: u64 = 0;

        // Add the package to the cache
        self.ifs_packages.push(file_path.display().to_string());
        // Get index
        let package_index = self.ifs_packages.len() - 1;

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
        for _ in 0..bet_table.entry_count {
            // New entry, set index
            let mut entry = IFSFileEntry {
                file_package_index: package_index,
                ..Default::default()
            };

            // Read data
            // TODO: file_size is always == compressed_size? flags is always = 0x80000000?
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

            entry.flags =
                utils::read_bit_len_int(&table_entries, bit_offset, bet_table.bit_count_flag_size)
                    as usize;
            bit_offset += bet_table.bit_count_flag_size;

            // Skip over unknown data
            bit_offset += bet_table.bit_count_hash_size;
            bit_offset += bet_table.hash_array_size;

            // Grab the hash and use as the key
            let name_hash =
                utils::read_bit_len_uint(&table_hashes, hash_offset, bet_table.hash_size_total);
            hash_offset += bet_table.hash_size_total;

            // Check for list file, starts at header size
            if entry.file_position == header.header_size as usize && entry.flags == 0x80000000 {
                list_file_hash = name_hash;
            }

            // Add it
            file_entries.insert(name_hash, entry);
        }

        // End --------------------------------------------------------------

        // Find `(listfile)`, it provides the names of all file entries
        let list_file = file_entries
            .get(&list_file_hash)
            .ok_or("List file not found")?;

        // Read the list file
        let list_file_buffer =
            file.read_array_at::<u8>(list_file.file_position as u64, list_file.file_size)?;

        // To string
        let list_file = match String::from_utf8(list_file_buffer) {
            Ok(s) => s,
            // Silent failure
            Err(_) => return Ok(()),
            // Err(e) => return Err(format!("Invalid UTF-8 in list file: {}", e).into()),
        };

        // Find list
        // TODO:
        if !list_file.contains(".lst\r\n") {
            return Err("Invalid LST file".into());
        }

        // Split by line, trim the line and check for valid entries
        for line in list_file.lines().map(str::trim) {
            if line.is_empty() {
                continue;
            }

            // Calculate XXHash for our searching
            let entry_hash = line.hash_xxh64();

            // Jenkins hashlittle2 for HET tables
            let bet_file_hash = IFSCrypt::bet_hash(line, het_table.hash_entry_size);

            // Check for entry in file
            if let Some(entry) = file_entries.get_mut(&bet_file_hash) {
                entry.path = line.to_string();

                // Add the new file
                match self.ifs_files.entry(entry_hash) {
                    Entry::Vacant(v) => {
                        v.insert(entry.to_owned());
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

                        println!("{}", msg);*/

                        o.insert(entry.to_owned());
                    }
                }
            }
        }

        Ok(())
    }

    pub fn get_entry_hash(entry_path: &str) -> u64 {
        entry_path.hash_xxh64()
    }

    pub fn entry_exists_from_path(&self, entry_path: &str) -> bool {
        let entry_hash = Self::get_entry_hash(entry_path);
        self.ifs_files.contains_key(&entry_hash)
    }

    pub fn try_get_entry(&self, entry_path: &str) -> io::Result<&IFSFileEntry> {
        let entry_hash = Self::get_entry_hash(entry_path);
        self.ifs_files.get(&entry_hash).ok_or(io::Error::new(
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
        let entry_path = &entry.path;

        // Open the package for reading
        let package_path = &self.ifs_packages[entry.file_package_index];
        let mut reader = File::open(package_path)?;

        // Read the data, it's encrypted for some types
        let entry_data =
            reader.read_array_at::<u8>(entry.file_position as u64, entry.compressed_size)?;

        // Not encrypted
        // TODO: Any flags to check if encrypted?
        if entry_path.ends_with(".ff") || entry_path.ends_with(".lst") {
            return Ok(entry_data);
        };

        let mut enc_data_reader = Cursor::new(&entry_data);

        // The packed size
        let packed_size = entry_data.len() - 4;

        // The unpacked size is appended to the end
        enc_data_reader.seek(SeekFrom::End(-4))?;
        let unpacked_size = enc_data_reader.read_struct::<u32>()? as usize;

        // Read the nonce for the IV
        let file_name = Path::new(entry_path).file_name().unwrap().to_str().unwrap();
        let nonce = file_name.hash_crc32(file_name.len() as u32);

        // Build the IV
        let mut file_iv = FileIV {
            nonce,
            unpacked_size: unpacked_size as u32,
            iv_counter: Default::default(),
        };

        // Allocate the buffers
        let mut encrypted_buffer = vec![0u8; 0x8000];
        let mut decrypted_buffer = vec![0u8; packed_size];
        let mut result_buffer = vec![0u8; unpacked_size];

        let mut packed_offset = 0;

        // Go back to start
        enc_data_reader.set_position(0);

        // Decrypt chunks
        while packed_offset < packed_size {
            let left = packed_size - packed_offset;
            let block_size = left.min(0x8000);

            // Shift the index
            file_iv.iv_counter = IVPartLength {
                iv_index: packed_offset as u32,
                iv_block_size: block_size as u32,
            };

            // Set the IV Counter
            let mut cipher = Self::generate_cipher(&file_iv.to_bytes());

            // Read the data
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

        // Decompress
        if packed_offset > 0 {
            assert_eq!(decrypted_buffer[..2], [0x78, 0xDA], "Invalid zlib header");
            let mut decoder = ZlibDecoder::new(decrypted_buffer.as_slice());

            decoder.read_exact(&mut result_buffer)?;
        }

        Ok(result_buffer)
    }
}

#[test]
fn test_load_image_file() {
    let iips_path = "E:/Downloads/codol_final/IIPS/IIPSDownload";
    let ifs_path = "lf_hi_init_common_marketplace_8_V38.1.ifs";
    let entry_path = "hires/images/sco_l115dragonboat_col.iwi";
    let expected = "IWi".to_string();

    let mut ifs = IFSLib::new();

    let ifs_path = Path::new(iips_path).join(ifs_path);
    ifs.load_package(ifs_path.as_path()).unwrap();
    let entry = ifs.read_entry_from_path(entry_path).unwrap();

    let got = String::from_utf8(entry[..3].to_vec()).unwrap();

    assert_eq!(
        got, expected,
        "Entry data mismatch for {:?}: got {:?}, expected {:?}",
        entry_path, got, expected
    );
}

#[test]
fn test_attach_iips() {
    let iips_path = "E:/Downloads/codol_final/IIPS/IIPSDownload";
    let entry_path = "hires/images/sco_l115dragonboat_col.iwi";
    let expected = "IWi".to_string();

    let mut ifs = IFSLib::new();

    ifs.load_packages(Path::new(iips_path)).unwrap();
    let entry = ifs.read_entry_from_path(entry_path).unwrap();

    let got = String::from_utf8(entry[..3].to_vec()).unwrap();

    assert_eq!(
        got, expected,
        "Entry data mismatch for {:?}: got {:?}, expected {:?}",
        entry_path, got, expected
    );
}

#[test]
fn test_load_surf_file() {
    let iips_path = "E:/Downloads/codol_final/IIPS/IIPSDownload";
    let entry_path = "main/models/wea_scarsapr_slogan_lod210";
    let expected = 1u32.to_le_bytes();

    let mut ifs = IFSLib::new();

    ifs.load_packages(Path::new(iips_path)).unwrap();
    let entry = ifs.read_entry_from_path(entry_path).unwrap();

    let got = &entry[..4];

    assert_eq!(
        got, expected,
        "Entry data mismatch for {:?}: got {:?}, expected {:?}",
        entry_path, got, expected
    );
}
