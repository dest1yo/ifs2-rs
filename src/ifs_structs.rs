use bitflags::bitflags;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IFSHeader {
    pub magic: u32,
    pub header_size: u32,
    pub format_version: u16,
    pub sector_size_shift: u16,

    pub archive_size: u64,
    pub bet_table_pos: u64,
    pub het_table_pos: u64,
    pub md5_table_pos: u64,
    pub bitmap_pos: u64,

    pub het_table_size: u64,
    pub bet_table_size: u64,
    pub md5_table_size: u64,
    pub bitmap_size: u64,

    pub md5_piece_size: u32,
    pub raw_chunk_size: u32,
}

impl IFSHeader {
    pub fn verify_magic(&self) -> bool {
        self.magic == 0x7366696E // 'nifs'
    }

    pub fn max_sector_size(&self) -> u32 {
        0x200 << self.sector_size_shift
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IFSHetHeader {
    pub magic: u32,
    pub version: u32,
    pub data_size: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IFSBetHeader {
    pub magic: u32,
    pub version: u32,
    pub data_size: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IFSHetTable {
    pub table_size: u32,
    pub entry_count: u32,
    pub hash_table_size: u32,
    pub hash_entry_size: u32,
    pub index_size_total: u32,
    pub index_size_extra: u32,
    pub index_size: u32,
    pub block_table_size: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IFSBetTable {
    pub table_size: u32,
    pub entry_count: u32,
    pub table_entry_size: u32,

    pub bit_index_file_pos: u32,
    pub bit_index_file_size: u32,
    pub bit_index_cmp_size: u32,
    pub bit_index_flag_pos: u32,
    pub bit_index_hash_pos: u32,

    pub unknown_repeat_pos: u32,

    pub bit_count_file_pos: u32,
    pub bit_count_file_size: u32,
    pub bit_count_cmp_size: u32,
    pub bit_count_flag_size: u32,
    pub bit_count_hash_size: u32,

    pub unknown_zero: u32,

    pub hash_size_total: u32,
    pub hash_size_extra: u32,
    pub hash_size: u32,

    pub hash_part1: u32,
    pub hash_part2: u32,

    pub hash_array_size: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FileIV {
    pub nonce: u32,
    pub unpacked_size: u32,
    pub iv_counter: IVPartLength,
}

impl FileIV {
    pub fn to_bytes(self) -> [u8; 16] {
        let mut bytes = [0u8; 16];

        bytes[..4].copy_from_slice(&self.nonce.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.unpacked_size.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.iv_counter.to_bytes());

        bytes
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct IVPartLength {
    pub iv_index: u32,
    pub iv_block_size: u32,
}

impl IVPartLength {
    pub fn to_bytes(self) -> [u8; 8] {
        let mut bytes = [0u8; 8];

        bytes[..4].copy_from_slice(&self.iv_index.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.iv_block_size.to_le_bytes());

        bytes
    }
}

#[derive(Debug, Clone, Default)]
pub struct IFSFileEntry {
    pub file_path: String,
    pub file_package_index: usize,
    pub file_position: usize,
    pub file_size: usize,
    pub compressed_size: usize,
    pub flags: IFSFileFlags,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct IFSFileFlags: u32 {
        /// File is compressed using PKWARE Data Compression Library
        const IMPLODE       = 0x00000100;
        /// File is compressed using combination of algorithms
        const COMPRESS      = 0x00000200;
        /// File is encrypted
        const ENCRYPTED     = 0x00010000;
        /// Encryption key adjusted by file offset
        const KEY_ADJUSTED  = 0x00020000;
        /// File is a patch file
        const PATCH_FILE    = 0x00100000;
        /// File is stored as single unit (not split into sectors)
        const SINGLE_UNIT   = 0x01000000;
        /// File is marked for deletion
        const DELETE_MARKER = 0x02000000;
        /// File has checksums for each sector (ADLER32, not CRC32)
        const SECTOR_CRC    = 0x04000000;
        /// File exists in the archive
        const EXISTS        = 0x80000000;
        // Unknown flags
        const UNKNOWN_1     = 0x08000000;
    }
}

impl IFSFileFlags {
    /// Check if the file is compressed
    pub fn is_compressed(self) -> bool {
        self.intersects(IFSFileFlags::IMPLODE | IFSFileFlags::COMPRESS)
    }

    /// Check if the file is encrypted
    pub fn is_encrypted(self) -> bool {
        self.contains(IFSFileFlags::ENCRYPTED)
    }

    /// Check if the file is stored as a single unit
    pub fn is_single_unit(self) -> bool {
        self.contains(IFSFileFlags::SINGLE_UNIT)
    }

    /// Check if the file has sector CRCs
    pub fn has_sector_crc(self) -> bool {
        self.contains(IFSFileFlags::SECTOR_CRC)
    }

    /// Check if the file exists
    pub fn exists(self) -> bool {
        self.contains(IFSFileFlags::EXISTS)
    }

    /// Check if the file uses fixed key encryption
    pub fn has_fix_key(self) -> bool {
        self.contains(IFSFileFlags::KEY_ADJUSTED)
    }

    /// Check if the file is a patch file
    pub fn is_patch_file(self) -> bool {
        self.contains(IFSFileFlags::PATCH_FILE)
    }
}
