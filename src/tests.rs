#[cfg(test)]

mod tests {
    use crate::IFSLib;
    use std::path::Path;

    // Change this to your IIPSDownload directory path
    const IIPS_PATH: &str = "E:/Downloads/codol_final/IIPS/IIPSDownload";

    // load single package, and read iwi file entry
    #[test]
    fn test_load_image_file() {
        let ifs_name = "lf_hi_init_common_marketplace_8_V38.1.ifs";
        let ifs_path = Path::new(IIPS_PATH).join(ifs_name);

        let entry_path = "hires\\images\\sco_l115dragonboat_col.iwi";
        let expected = b"IWi";

        let mut ifs = IFSLib::new();
        ifs.load_package(&ifs_path).unwrap();

        let entry = ifs.read_entry_from_path(entry_path).unwrap();
        let got = &entry[..3];

        assert_eq!(
            got, expected,
            "Entry data mismatch for {:?}: got {:?}, expected {:?}",
            entry_path, got, expected
        );
    }

    // load all packages from directory, and read iwi file entry
    #[test]
    fn test_attach_iips() {
        let entry_path = "hires\\images\\sco_l115dragonboat_col.iwi";
        let expected = b"IWi";

        let mut ifs = IFSLib::new();
        ifs.load_packages(Path::new(IIPS_PATH)).unwrap();

        assert_eq!(ifs.entry_exists_from_path(&entry_path), true);

        let entry = ifs.read_entry_from_path(entry_path).unwrap();
        let got = &entry[..3];

        assert_eq!(
            got, expected,
            "Entry data mismatch for {:?}: got {:?}, expected {:?}",
            entry_path, got, expected
        );
    }

    // load all packages from directory, and read surf file entry
    #[test]
    fn test_load_surf_file() {
        let entry_path = "main\\models\\wea_scarsapr_slogan_lod210";
        let expected = 1u32.to_le_bytes();

        let mut ifs = IFSLib::new();
        ifs.load_packages(Path::new(IIPS_PATH)).unwrap();

        let entry = ifs.read_entry_from_path(entry_path).unwrap();
        let got = &entry[..4];

        assert_eq!(
            got, expected,
            "Entry data mismatch for {:?}: got {:?}, expected {:?}",
            entry_path, got, expected
        );
    }

    // load all packages from directory, and read sound file entry
    #[test]
    fn test_read_sound() {
        let entry_path = "main/sound/voiceovers/codo_mp/ancr/scar/AB_1mc_use_moab_01.mp3"
            .to_lowercase()
            .replace('/', "\\");
        let expected = b"ID3";

        let mut ifs = IFSLib::new();
        ifs.load_packages(Path::new(IIPS_PATH)).unwrap();

        assert_eq!(ifs.entry_exists_from_path(&entry_path), true);

        let entry = ifs.read_entry_from_path(entry_path.as_str()).unwrap();
        let got = &entry[..3];

        assert_eq!(
            got, expected,
            "Entry data mismatch for {:?}: got {:?}, expected {:?}",
            entry_path, got, expected
        );
    }

    // for verifying new method to read .lst works, but we don't use .lst anymore now
    #[test]
    fn test_load_surf_file_v2() {
        let ifs_name = "lf_init_common_marketplace_4_V46.1.ifs";
        let ifs_path = Path::new(IIPS_PATH).join(ifs_name);

        let entry_path = "main\\models\\wea_m4a1tech_m4a1mwcrosspro_vmgun10";
        let expected = 1u32.to_le_bytes();

        let mut ifs = IFSLib::new();
        ifs.load_package(&ifs_path).unwrap();

        let entry = ifs.read_entry_from_path(entry_path).unwrap();
        let got = &entry[..4];

        assert_eq!(
            got, expected,
            "Entry data mismatch for {:?}: got {:?}, expected {:?}",
            entry_path, got, expected
        );
    }

    // no .lst file in this ifs, we use list file instead
    #[test]
    fn test_load_ifs_without_lst() {
        let ifs_name = "ff_dlc18_mp_hardhat_sh_V37.1.ifs";
        let ifs_path = Path::new(IIPS_PATH).join(ifs_name);

        let mut ifs = IFSLib::new();
        ifs.load_package(&ifs_path).unwrap();
    }

    // list file encrypted, and compressed with 2 sectors
    #[test]
    fn test_load_ifs_2_sectors() {
        let ifs_name = "lf_dlc17_za_coliseum_V9.ifs";
        let ifs_path = Path::new(IIPS_PATH).join(ifs_name);

        let mut ifs = IFSLib::new();
        ifs.load_package(&ifs_path).unwrap();
    }

    // list file encrypted, but not compressed
    #[test]
    fn test_load_ifs_v2() {
        let ifs_name = "lf_dlc18_mp_hardhat_sh_V3.1.ifs";
        let ifs_path = Path::new(IIPS_PATH).join(ifs_name);

        let mut ifs = IFSLib::new();
        ifs.load_package(&ifs_path).unwrap();
    }

    // load single package, and read ff file entry
    #[test]
    fn test_read_ff() {
        let ifs_name = "ff_init_common_gfx_V109.ifs";
        let ifs_path = Path::new(IIPS_PATH).join(ifs_name);

        let entry_path = "client_shipretail\\chinese\\code_pre_gfx_mp.ff";
        let expected = b"IWff";

        let mut ifs = IFSLib::new();
        ifs.load_package(&ifs_path).unwrap();

        let entry = ifs.read_entry_from_path(entry_path).unwrap();
        let got = &entry[..4];

        assert_eq!(
            got, expected,
            "Entry data mismatch for {:?}: got {:?}, expected {:?}",
            entry_path, got, expected
        );
    }
}
