mod common;

use std::fs;

const LODASH_INTEGRITY: &str = "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==";

fn run_with_integrity(integrity: &str) -> (Option<i32>, String) {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(
        dir.path().join("package.json"),
        r#"{"dependencies":{"lodash":"4.17.21"}}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("package-lock.json"),
        format!(
            r#"{{"lockfileVersion":3,"packages":{{"":{{"name":"app"}},"node_modules/lodash":{{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz","integrity":"{integrity}"}}}}}}"#
        ),
    )
    .unwrap();
    let output = common::gyrseek()
        .args(["npm", "ci"])
        .current_dir(dir.path())
        .env_remove("GYRSEEK_TEST_SKIP_LOCK_VERIFY")
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .output()
        .expect("gyrseek process should run");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).to_string(),
    )
}

/// Needs the network: the public hash of lodash 4.17.21 is fetched from registry.npmjs.org.
#[test]
fn a_lockfile_hash_the_public_registry_does_not_publish_is_refused_before_the_scan() {
    let (code, out) = run_with_integrity("sha512-AAAA");
    assert_eq!(code, Some(1));
    assert!(
        out.contains("does not publish for this version"),
        "got: {out}"
    );
    assert!(!out.contains("Clear behavioral report"), "got: {out}");
}

#[test]
fn the_real_lockfile_hash_passes_the_check() {
    let (_, out) = run_with_integrity(LODASH_INTEGRITY);
    assert!(!out.contains("cannot be shown to be files"), "got: {out}");
}
