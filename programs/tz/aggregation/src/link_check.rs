use op_succinct_client_utils::boot::BootInfoStruct;

pub fn check_link(boot_infos: &[BootInfoStruct]) {
    assert!(!boot_infos.is_empty(), "empty boot_infos");
    for pair in boot_infos.windows(2) {
        let (prev, curr) = (&pair[0], &pair[1]);
        assert_eq!(prev.l2PostRoot, curr.l2PreRoot, "boot_info chain break");
        assert_eq!(
            prev.rollupConfigHash, curr.rollupConfigHash,
            "rollupConfigHash diverges across boot_infos"
        );
    }
}
