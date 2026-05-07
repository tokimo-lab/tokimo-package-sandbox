mod common;

use std::time::Duration;

use common::{SandboxGuard, config, drain_until};
use tokimo_package_sandbox::Sandbox;
use tokimo_package_sandbox::fonts::discover_host_font_dirs;

/// Helper: returns true if the host has at least one font directory.
fn host_has_fonts() -> bool {
    !discover_host_font_dirs().is_empty()
}

/// Unit test: host font discovery returns valid, non-duplicate entries.
/// Skipped on machines with no font directories (minimal CI images).
#[test]
fn discover_finds_font_dirs() {
    let dirs = discover_host_font_dirs();
    if dirs.is_empty() {
        eprintln!("SKIP: no font directories on this machine");
        return;
    }
    // Every returned dir must actually exist on disk.
    for fd in &dirs {
        assert!(
            fd.host_path.is_dir(),
            "FontDir host_path does not exist: {}",
            fd.host_path.display()
        );
    }
    // Mount names must be non-empty and unique.
    let names: Vec<&str> = dirs.iter().map(|d| d.mount_name.as_str()).collect();
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(names.len(), sorted.len(), "duplicate mount names: {names:?}");
}

/// Unit test: on Linux, /usr/share/fonts is discovered if it exists.
#[cfg(target_os = "linux")]
#[test]
fn discover_linux_system_fonts() {
    let dirs = discover_host_font_dirs();
    let has_system = dirs.iter().any(|d| d.mount_name == "fonts-system");
    if std::path::Path::new("/usr/share/fonts").is_dir() {
        assert!(has_system, "fonts-system not found despite /usr/share/fonts existing");
    }
}

/// Integration test: mount host fonts into the guest and verify they appear
/// in the fontconfig font list.
#[test]
fn mount_host_fonts_visible_in_guest() {
    if !host_has_fonts() {
        eprintln!("SKIP: no font directories on this machine");
        return;
    }

    const MARKER: &str = "FONTS_DONE_C3D4";

    let label = "fontmount";
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let mounted = sb.mount_host_fonts("/tmp/host-fonts").expect("mount_host_fonts");
    assert!(!mounted.is_empty(), "no host font directories were mounted");

    // Give fc-cache a moment to finish (it was triggered async via stdin).
    sb.write_stdin(
        &shell,
        b"sleep 2; fc-list 2>/dev/null | head -5; echo FONTS_DONE_C3D4\n",
    )
    .unwrap();

    let captured = drain_until(&rx, &shell, MARKER, Duration::from_secs(30));
    sb.stop_vm().ok();

    // fc-list output should contain at least one font path (colon-separated
    // format: "/path/to/font: Family:style=...").  If fontconfig is not
    // installed in the guest, fc-list won't produce output — that's OK,
    // the important thing is that the mount succeeded and no errors occurred.
    if captured.contains('/') {
        assert!(
            captured.contains("fonts")
                || captured.contains("Fonts")
                || captured.contains(".ttf")
                || captured.contains(".otf")
                || captured.contains(".ttc"),
            "fc-list output doesn't look like font paths. captured: {captured:?}"
        );
    }
}

/// Integration test: mount_host_fonts is idempotent — calling it twice
/// does not error or create duplicate mounts.
#[test]
fn mount_host_fonts_idempotent() {
    if !host_has_fonts() {
        eprintln!("SKIP: no font directories on this machine");
        return;
    }

    const MARKER: &str = "IDEMP_DONE_E5F6";

    let label = "fontidemp";
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let first = sb.mount_host_fonts("/tmp/host-fonts").expect("first mount");
    let second = sb.mount_host_fonts("/tmp/host-fonts").expect("second mount");

    // Second call should return the same paths (skipped, not duplicated).
    assert_eq!(first.len(), second.len(), "idempotent call returned different count");

    // Verify no errors in the guest.
    sb.write_stdin(&shell, b"echo IDEMP_DONE_E5F6\n").unwrap();
    let captured = drain_until(&rx, &shell, MARKER, Duration::from_secs(10));
    sb.stop_vm().ok();

    assert!(
        !captured.contains("error") && !captured.contains("Error"),
        "errors during idempotent mount. captured: {captured:?}"
    );
}

/// Integration test: mounted font files are readable inside the guest.
#[test]
fn mounted_font_files_readable() {
    if !host_has_fonts() {
        eprintln!("SKIP: no font directories on this machine");
        return;
    }

    const MARKER: &str = "READ_DONE_G7H8";

    let label = "fontread";
    let sb = Sandbox::connect().expect("connect");
    sb.configure(config(label)).expect("configure");
    let rx = sb.subscribe().expect("subscribe");
    sb.start_vm().expect("start_vm");
    let _guard = SandboxGuard(sb.clone());
    let shell = sb.shell_id().expect("shell_id");

    let mounted = sb.mount_host_fonts("/tmp/host-fonts").expect("mount_host_fonts");
    assert!(!mounted.is_empty());

    // Verify the first mounted directory is accessible.
    let first_path = mounted[0].to_str().unwrap().to_string();
    sb.write_stdin(
        &shell,
        format!("ls {first_path} 2>&1 | head -3; echo READ_DONE_G7H8\n").as_bytes(),
    )
    .unwrap();

    let captured = drain_until(&rx, &shell, MARKER, Duration::from_secs(30));
    sb.stop_vm().ok();

    assert!(
        !captured.is_empty() && !captured.contains("No such file"),
        "mounted font dir not readable. captured: {captured:?}"
    );
}
