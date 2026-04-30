//! Demo: mount multiple host directories into a macOS VZ sandbox session.
//!
//! Run on macOS with kernel/initrd/rootfs artifacts available
//! (`~/.tokimo/{kernel,rootfs,initrd}` or via `TOKIMO_VZ_*` env vars):
//!
//! ```text
//! cargo run --example vz_multi_mount
//! ```

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use tokimo_package_sandbox::{Mount, NetworkPolicy, SandboxConfig, Session};

    let work = tempfile::tempdir()?;
    let rw = tempfile::tempdir()?;
    let ro = tempfile::tempdir()?;
    fs::write(rw.path().join("hi.txt"), "hello from host (RW)")?;
    fs::write(ro.path().join("readme.txt"), "read me (RO)")?;

    let cfg = SandboxConfig::new(work.path())
        .network(NetworkPolicy::Blocked)
        .mount(Mount {
            host: rw.path().to_path_buf(),
            guest: Some("/mnt/rw".into()),
            read_only: false,
        })
        .mount(Mount {
            host: ro.path().to_path_buf(),
            guest: Some("/mnt/ro".into()),
            read_only: true,
        });

    let mut sess = Session::open(&cfg)?;
    println!("RW read   : {}", sess.exec("cat /mnt/rw/hi.txt")?.stdout.trim());
    println!("RO read   : {}", sess.exec("cat /mnt/ro/readme.txt")?.stdout.trim());

    let _ = sess.exec("printf 'from-guest' > /mnt/rw/guest.txt")?;
    println!("host sees : {}", fs::read_to_string(rw.path().join("guest.txt"))?);

    let attempt = sess.exec("printf x > /mnt/ro/should-fail.txt 2>&1; echo rc=$?")?;
    println!("RO write attempt: {}", attempt.stdout.trim());
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("vz_multi_mount: macOS-only example");
}
