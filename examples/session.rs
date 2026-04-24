//! Demonstrates a persistent sandbox session: open once, run multiple
//! commands sharing filesystem and shell state, then close.
//!
//! cargo run --example session

use tokimo_package_sandbox::{NetworkPolicy, ResourceLimits, SandboxConfig, Session};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let work = std::env::temp_dir().join("tps-session-demo");
    std::fs::create_dir_all(&work)?;

    let cfg = SandboxConfig::new(&work)
        .network(NetworkPolicy::Blocked)
        .limits(ResourceLimits {
            timeout_secs: 30,
            ..Default::default()
        });

    let mut sess = Session::open(&cfg)?;

    // (1) Create a file in the first call.
    let r = sess.exec("touch hello && echo created")?;
    println!("[1] rc={} stdout={:?}", r.exit_code, r.stdout.trim());

    // (2) The file is still there in the second call.
    let r = sess.exec("ls -la")?;
    println!("[2] rc={} stdout=\n{}", r.exit_code, r.stdout);
    assert!(r.stdout.contains("hello"), "file did not persist!");

    // (3) Environment variables persist across calls.
    sess.exec("export GREETING='hi from sandbox'")?;
    let r = sess.exec("echo \"$GREETING\"")?;
    println!("[3] rc={} stdout={:?}", r.exit_code, r.stdout.trim());
    assert_eq!(r.stdout.trim(), "hi from sandbox");

    // (4) cwd changes persist.
    sess.exec("mkdir -p sub && cd sub && touch nested")?;
    let r = sess.exec("pwd && ls")?;
    println!("[4] rc={} stdout=\n{}", r.exit_code, r.stdout);
    assert!(r.stdout.contains("/sub"));
    assert!(r.stdout.contains("nested"));

    // (5) Non-zero exit code is reported.
    let r = sess.exec("false")?;
    println!("[5] rc={} (expected 1)", r.exit_code);
    assert_eq!(r.exit_code, 1);

    // (6) Stderr is captured separately.
    let r = sess.exec("echo to-stderr >&2 ; echo to-stdout")?;
    println!(
        "[6] rc={} stdout={:?} stderr={:?}",
        r.exit_code,
        r.stdout.trim(),
        r.stderr.trim()
    );
    assert_eq!(r.stdout.trim(), "to-stdout");
    assert_eq!(r.stderr.trim(), "to-stderr");

    // (7) Multi-line / heredoc-using user code works.
    let r = sess.exec(
        r#"for i in 1 2 3; do
  echo "line $i"
done"#,
    )?;
    println!("[7] rc={} stdout=\n{}", r.exit_code, r.stdout);
    assert!(r.stdout.contains("line 1"));
    assert!(r.stdout.contains("line 3"));

    sess.close()?;
    println!("\nAll session assertions passed ✓");
    Ok(())
}
