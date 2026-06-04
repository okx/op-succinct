use op_succinct_client_utils::boot::BootInfoStruct;

pub fn check_link(boot_infos: &[BootInfoStruct]) {
    assert!(!boot_infos.is_empty(), "empty boot_infos");
    for pair in boot_infos.windows(2) {
        let (prev, curr) = (&pair[0], &pair[1]);
        assert_eq!(prev.l2PostRoot, curr.l2PreRoot, "boot_info chain break");
        // rollupConfigHash is not checked here — tradezone has no rollup config; the field is
        // a ZERO placeholder in BootInfoStruct and the on-chain ROLLUP_CONFIG_HASH immutable is
        // also deployed as ZERO. No semantic constraint to enforce across boot_infos.
    }
}
