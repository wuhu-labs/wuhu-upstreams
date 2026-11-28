//! `build.sh linux` packages only the archive its own build wrote: on a reused target directory
//! (CI caches `iroh/target`), a failed build or one that wrote no archive must not package the
//! archive a build before it left behind.
//!
//! Each case runs a copy of the script against a stand-in `cargo` that passes `cargo test` and
//! does what the case says for `cargo build`.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const TARGET: &str = "x86_64-unknown-linux-gnu";

/// A copy of what build.sh reads, in a fresh folder, with a stale archive from an earlier build
/// in its target directory.
fn workspace(name: &str) -> PathBuf {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root =
        std::env::temp_dir().join(format!("wuhu-iroh-build-sh-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("crate/include")).unwrap();
    for file in ["build.sh", "Cargo.toml", "Cargo.lock", "PROVENANCE.md"] {
        fs::copy(here.join(file), root.join("crate").join(file)).unwrap();
    }
    for file in ["wuhu_iroh.h", "module.modulemap"] {
        fs::copy(
            here.join("include").join(file),
            root.join("crate/include").join(file),
        )
        .unwrap();
    }
    let release = root.join(format!("crate/target/{TARGET}/release"));
    fs::create_dir_all(&release).unwrap();
    fs::write(release.join("libwuhu_iroh.a"), "stale").unwrap();
    fs::create_dir_all(root.join("bin")).unwrap();
    root
}

/// Runs build.sh linux with a `cargo` whose `build` runs `build` (sh, in the crate folder, with
/// the archive's path in $LIB). Returns whether it succeeded and the archive it packaged, if any.
fn run(root: &Path, build: &str) -> (bool, Option<String>) {
    let stub = root.join("bin/cargo");
    fs::write(
        &stub,
        format!(
            "#!/bin/sh\ncase \"$1\" in\nbuild) LIB=\"${{CARGO_TARGET_DIR:-target}}/{TARGET}/release/libwuhu_iroh.a\"; {build} ;;\n*) exit 0 ;;\nesac\n"
        ),
    )
    .unwrap();
    Command::new("chmod").arg("+x").arg(&stub).status().unwrap();
    let path = format!(
        "{}:{}",
        root.join("bin").display(),
        std::env::var("PATH").unwrap()
    );
    let out = root.join("out");
    let status = Command::new("sh")
        .arg(root.join("crate/build.sh"))
        .arg("linux")
        .arg(&out)
        .env("PATH", path)
        .env_remove("CARGO_TARGET_DIR")
        .status()
        .unwrap();
    let tarball = fs::read_dir(&out)
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| {
            e.file_name()
                .to_string_lossy()
                .ends_with("-linux-x86_64.tar.gz")
        })
        .map(|e| e.path());
    let packaged = tarball.map(|tarball| {
        let listing = Command::new("tar")
            .arg("-xzOf")
            .arg(&tarball)
            .arg("./lib/libwuhu_iroh.a")
            .output()
            .unwrap();
        String::from_utf8_lossy(&listing.stdout).into_owned()
    });
    (status.success(), packaged)
}

fn linux_x86_64() -> bool {
    cfg!(all(target_os = "linux", target_arch = "x86_64"))
}

#[test]
fn a_failed_build_packages_nothing() {
    if !linux_x86_64() {
        return;
    }
    let root = workspace("failed");
    let (ok, packaged) = run(&root, "echo 'error: could not compile' >&2; exit 101");
    let _ = fs::remove_dir_all(&root);
    assert!(!ok, "build.sh succeeded although cargo build failed");
    assert_eq!(packaged, None, "packaged the stale archive");
}

#[test]
fn a_build_that_wrote_no_archive_packages_nothing() {
    if !linux_x86_64() {
        return;
    }
    let root = workspace("none");
    let (ok, packaged) = run(&root, "exit 0");
    let _ = fs::remove_dir_all(&root);
    assert!(!ok, "build.sh succeeded without a fresh archive");
    assert_eq!(packaged, None, "packaged the stale archive");
}

#[test]
fn a_build_packages_the_archive_it_wrote() {
    if !linux_x86_64() {
        return;
    }
    let root = workspace("fresh");
    let (ok, packaged) = run(
        &root,
        "mkdir -p \"$(dirname \"$LIB\")\"; printf fresh > \"$LIB\"; echo 'note: native-static-libs: -lc'",
    );
    let _ = fs::remove_dir_all(&root);
    assert!(ok, "build.sh failed");
    assert_eq!(packaged.as_deref(), Some("fresh"));
}
