//! End-to-end smoke test for the Windows sandbox backend.
//!
//! Run as: `cargo run --example smoke`
//!
//! Requires `tokimo-sandbox-svc` to be running (service-mode or `--console`).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tokimo_package_sandbox::{
    ConfigureParams, Event, ExecOpts, NetworkPolicy, Plan9Share, Sandbox,
};

fn banner(s: &str) {
    println!("\n========== {} ==========", s);
}

fn run_one(sb: &Sandbox, label: &str, argv: &[&str]) -> bool {
    let t = Instant::now();
    match sb.exec(argv, ExecOpts::default()) {
        Ok(r) => {
            let stdout = r.stdout_str();
            let stderr = r.stderr_str();
            println!(
                "[{label}] exit={} sig={:?} t={}ms\n  stdout: {}\n  stderr: {}",
                r.exit_code,
                r.signal,
                t.elapsed().as_millis(),
                stdout.lines().take(3).collect::<Vec<_>>().join(" | "),
                stderr.lines().take(3).collect::<Vec<_>>().join(" | "),
            );
            r.success()
        }
        Err(e) => {
            println!("[{label}] ERR: {e}");
            false
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host_share = std::env::current_dir()?.join("examples");
    println!("host share dir: {}", host_share.display());

    banner("connect");
    let sb = Sandbox::connect()?;
    println!("connected to svc");

    banner("subscribe");
    let rx = sb.subscribe()?;
    let collected: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(vec![]));
    {
        let collected = collected.clone();
        thread::spawn(move || {
            while let Ok(ev) = rx.recv() {
                if let Ok(mut g) = collected.lock() {
                    g.push(ev);
                }
            }
        });
    }

    banner("configure");
    let cfg = ConfigureParams {
        user_data_name: "smoke-test".into(),
        memory_mb: 2048,
        cpu_count: 2,
        plan9_shares: vec![Plan9Share {
            name: "host".into(),
            host_path: host_share.clone(),
            guest_path: PathBuf::from("/mnt/host"),
            read_only: false,
        }],
        network: NetworkPolicy::AllowAll,
        ..Default::default()
    };
    sb.configure(cfg)?;
    println!("configured");

    banner("createVm + startVm");
    sb.create_vm()?;
    println!("createVm OK");
    let t = Instant::now();
    sb.start_vm()?;
    println!("startVm OK, took {}ms", t.elapsed().as_millis());

    banner("status checks");
    println!("is_running         = {:?}", sb.is_running());
    println!("is_guest_connected = {:?}", sb.is_guest_connected());

    banner("basic exec");
    let mut pass = 0u32;
    let mut total = 0u32;
    let cases: &[(&str, &[&str])] = &[
        ("uname",    &["uname", "-a"]),
        ("id",       &["id"]),
        ("ls-root",  &["ls", "-la", "/"]),
        ("ls-mnt",   &["ls", "-la", "/mnt"]),
        ("ls-host",  &["ls", "-la", "/mnt/host"]),
        ("cat-cargo",&["sh", "-c", "head -5 /mnt/host/smoke.rs || echo MISSING"]),
        ("echo",     &["echo", "hello from sandbox"]),
        ("pipe",     &["sh", "-c", "echo a | tr a b"]),
        ("env",      &["sh", "-c", "echo PATH=$PATH"]),
        ("date",     &["date", "-u"]),
        ("which-sh", &["which", "sh"]),
        ("cpu",      &["sh", "-c", "nproc; cat /proc/meminfo | head -3"]),
    ];
    for (lab, argv) in cases {
        total += 1;
        if run_one(&sb, lab, argv) {
            pass += 1;
        }
    }

    banner("write to plan9 share from guest");
    total += 1;
    let r = sb.exec(
        &[
            "sh",
            "-c",
            "echo guest-wrote-this > /mnt/host/.smoke_marker && cat /mnt/host/.smoke_marker",
        ],
        ExecOpts::default(),
    )?;
    println!("guest write: exit={} stdout={:?}", r.exit_code, r.stdout_str().trim());
    if r.success() {
        // verify host side sees the file
        let marker = host_share.join(".smoke_marker");
        match std::fs::read_to_string(&marker) {
            Ok(c) => {
                let c = c.trim();
                println!("host reads back: {:?}", c);
                if c == "guest-wrote-this" {
                    pass += 1;
                    let _ = std::fs::remove_file(&marker);
                } else {
                    println!("MISMATCH");
                }
            }
            Err(e) => println!("host read FAILED: {e}"),
        }
    }

    banner("parallel exec");
    let n = 8;
    let sb2 = sb.clone();
    let t = Instant::now();
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let sb = sb2.clone();
            thread::spawn(move || {
                let r = sb
                    .exec(
                        &[
                            "sh".to_string(),
                            "-c".to_string(),
                            format!("sleep 0.5; echo job-{i}-$(hostname)"),
                        ],
                        ExecOpts::default(),
                    )
                    .map_err(|e| format!("{e}"))?;
                Ok::<_, String>((i, r.stdout_str()))
            })
        })
        .collect();
    let mut par_ok = 0;
    for h in handles {
        match h.join().unwrap() {
            Ok((i, out)) => {
                println!("  [{i}] {}", out.trim());
                par_ok += 1;
            }
            Err(e) => println!("  ERR {e}"),
        }
    }
    println!(
        "parallel: {par_ok}/{n} ok in {}ms (should be ~500ms not ~{}ms)",
        t.elapsed().as_millis(),
        n * 500
    );
    total += 1;
    if par_ok == n {
        pass += 1;
    }

    banner("spawn + write_stdin + events");
    let job = sb.spawn(
        &["sh", "-c", "while read line; do echo got:$line; done"],
        ExecOpts::default(),
    )?;
    println!("spawned job {}", job.as_str());
    sb.write_stdin(&job, b"alpha\n")?;
    sb.write_stdin(&job, b"beta\n")?;
    sb.write_stdin(&job, b"gamma\n")?;
    thread::sleep(Duration::from_millis(500));
    sb.kill(&job, 15)?;
    thread::sleep(Duration::from_millis(500));
    let evs = collected.lock().unwrap().clone();
    let mut stdout_chunks = Vec::new();
    let mut got_exit = false;
    for ev in &evs {
        match ev {
            Event::Stdout { id, data } if id == &job => {
                stdout_chunks.push(String::from_utf8_lossy(data).into_owned())
            }
            Event::Exit { id, exit_code, signal } if id == &job => {
                println!("  exit event: code={exit_code} sig={signal:?}");
                got_exit = true;
            }
            _ => {}
        }
    }
    let joined = stdout_chunks.join("");
    println!("  collected stdout: {:?}", joined);
    total += 1;
    if joined.contains("got:alpha") && joined.contains("got:beta") && joined.contains("got:gamma") && got_exit {
        pass += 1;
    }

    banner("env + cwd");
    total += 1;
    let r = sb.exec(
        &["sh", "-c", "echo cwd=$(pwd); echo MYV=$MYV"],
        ExecOpts {
            cwd: Some("/mnt/host".into()),
            env: vec![("MYV".into(), "smokevalue".into())],
            ..Default::default()
        },
    )?;
    println!("  {}", r.stdout_str().trim());
    if r.stdout_str().contains("cwd=/mnt/host") && r.stdout_str().contains("MYV=smokevalue") {
        pass += 1;
    }

    banner("non-zero exit");
    total += 1;
    let r = sb.exec(&["sh", "-c", "exit 42"], ExecOpts::default())?;
    println!("  exit={}", r.exit_code);
    if r.exit_code == 42 {
        pass += 1;
    }

    banner("stdout vs stderr separation");
    total += 1;
    let r = sb.exec(&["sh", "-c", "echo OUT; echo ERR 1>&2"], ExecOpts::default())?;
    println!("  stdout={:?} stderr={:?}", r.stdout_str().trim(), r.stderr_str().trim());
    if r.stdout_str().trim() == "OUT" && r.stderr_str().trim() == "ERR" {
        pass += 1;
    }

    banner("stop_vm");
    sb.stop_vm()?;
    println!("stopped");

    banner(&format!("RESULT: {pass}/{total} passed"));
    if pass == total {
        Ok(())
    } else {
        Err(format!("{}/{} failed", total - pass, total).into())
    }
}
