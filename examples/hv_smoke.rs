#[cfg(target_os = "windows")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let work = tempfile::tempdir()?;
    let cfg =
        tokimo_package_sandbox::SandboxConfig::new(work.path()).network(tokimo_package_sandbox::NetworkPolicy::Blocked);

    macro_rules! t {
        ($name:expr, $cmd:expr) => {{
            println!("=== {} ===", $name);
            let start = std::time::Instant::now();
            match tokimo_package_sandbox::run(&["/bin/bash", "-c", $cmd], &cfg) {
                Ok(out) => {
                    let ms = start.elapsed().as_millis();
                    let status = if out.exit_code == 0 { "PASS" } else { "FAIL" };
                    println!("{status} ({ms}ms) exit={}", out.exit_code);
                    if !out.stdout.trim().is_empty() {
                        println!("  stdout: {}", out.stdout.trim());
                    }
                    if !out.stderr.trim().is_empty() {
                        println!("  stderr: {}", out.stderr.trim());
                    }
                }
                Err(e) => println!("  ERROR: {e}"),
            }
        }};
    }

    println!("tokimo-package-sandbox Windows HV smoke test");
    println!("=============================================");

    t!("uname", "uname -a");
    t!("hostname", "hostname");
    t!("id", "id");
    t!("ls work dir", "ls -la /tmp/");
    t!("echo", "echo 'hello from HCS Linux VM'");
    t!("node --version", "node --version");
    t!("python3 --version", "python3 --version");
    t!("lua -v", "lua -v 2>&1 || true");
    t!("pandoc --version", "pandoc --version 2>&1 | head -1 || true");
    t!(
        "network blocked?",
        "curl -s --connect-timeout 2 https://example.com 2>&1 || true"
    );

    println!("\nDone.");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("hv_smoke: Windows-only (HCS Hyper-V backend)");
}
