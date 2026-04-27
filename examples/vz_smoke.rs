#[cfg(target_os = "macos")]
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

    t!("pnpm --version", "pnpm --version");
    t!("pnpm check", "which pnpm && pnpm --version && echo 'pnpm OK'");
    t!(
        "pip install (test python packages)",
        "python3 -c '
import requests, pandas, IPython
from rich import print as rprint
rprint(\"[green]✓ requests[/green] \" + requests.__version__)
rprint(\"[green]✓ pandas[/green]   \" + pandas.__version__)
rprint(\"[green]✓ ipython[/green]  \" + IPython.__version__)
'"
    );

    println!("\nDone.");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("vz_smoke: macOS-only (Virtualization.framework backend)");
}
