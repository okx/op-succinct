//! Enforcing coverage test: every in-scope service entrypoint must invoke the
//! shared startup config resolver (`init_startup_config`) before it first reads
//! configuration from the environment. A new in-scope binary that omits the call,
//! or orders it after its first `from_env(`, fails this test. This is a
//! filesystem scan — it needs no build of the binaries and stays correct as new
//! entrypoints are added. zkVM guest programs and test binaries are out of scope.

// In-scope resolver-consuming bin dirs (workspace-root-relative); zkVM guests + tests/* excluded.
const IN_SCOPE_BIN_DIRS: &[&str] =
    &["validity/bin", "fault-proof/bin", "scripts/prove/bin", "scripts/utils/bin"];

#[test]
fn every_in_scope_entrypoint_calls_startup_resolver_before_first_config_read() {
    let ws = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."); // utils/config-kms -> repo root
    let mut checked = 0;
    for dir in IN_SCOPE_BIN_DIRS {
        for entry in std::fs::read_dir(ws.join(dir)).expect("bin dir exists") {
            let p = entry.unwrap().path();
            if p.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap();
            let call = src
                .find("init_startup_config")
                .unwrap_or_else(|| panic!("{p:?} missing init_startup_config"));
            if let Some(first_from_env) = src.find("from_env(") {
                assert!(
                    call < first_from_env,
                    "{p:?}: startup resolver must precede first from_env("
                );
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 14, "expected 14 in-scope entrypoints");
}
