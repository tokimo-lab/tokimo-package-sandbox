//! Adversarial torture test: throws many AI-generated-style commands at a
//! single Session, including foreground commands with rogue `&`, daemons,
//! large outputs, syntax errors, intermixed bg jobs, etc. All must produce
//! correct results with no framing corruption between calls.

use std::time::{Duration, Instant};
use tokimo_package_sandbox::{NetworkPolicy, ResourceLimits, SandboxConfig, Session};

fn main() {
    let work = std::env::temp_dir().join("tps-torture");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let cfg = SandboxConfig::new(&work)
        .network(NetworkPolicy::Blocked)
        .limits(ResourceLimits {
            max_memory_mb: 512,
            max_file_size_mb: 64,
            timeout_secs: 30,
            ..Default::default()
        });

    let mut sess = Session::open(&cfg).expect("open");
    sess.set_exec_timeout(Duration::from_secs(20));

    let mut step = 0usize;
    macro_rules! check {
        ($desc:expr, $cond:expr) => {{
            step += 1;
            assert!($cond, "step {} ({}) FAILED", step, $desc);
            println!("  ✓ step {:>2}: {}", step, $desc);
        }};
    }

    // 1) Plain echo.
    let r = sess.exec("echo hello").unwrap();
    check!("plain echo", r.stdout.trim() == "hello" && r.exit_code == 0);

    // 2) Multi-statement & exit code propagation of last cmd.
    let r = sess.exec("true; false; true; (exit 7)").unwrap();
    check!("exit code last cmd", r.exit_code == 7);

    // 3) AI rogue `&`: backgrounds something noisy mid-command. Must NOT pollute
    //    next exec()'s framing.
    let r = sess.exec("yes garbage | head -5 & wait").unwrap();
    check!(
        "rogue & + wait",
        r.stdout.lines().filter(|l| *l == "garbage").count() == 5
    );

    // 4) Truly rogue: `&`-ed daemon left running (no wait). The next exec must
    //    still parse cleanly.
    let r = sess
        .exec("(while true; do echo SPAM; sleep 0.05; done) & disown; echo started")
        .unwrap();
    check!("rogue daemon backgrounded", r.stdout.contains("started"));

    // 5) Immediately after the rogue daemon: plain echo must NOT see SPAM.
    std::thread::sleep(Duration::from_millis(200));
    let r = sess.exec("echo CLEAN").unwrap();
    check!(
        "no spam pollution after rogue daemon",
        r.stdout.trim() == "CLEAN" && !r.stdout.contains("SPAM")
    );

    // 6) Even with the daemon still spamming, multiple rapid-fire execs work.
    for i in 0..10 {
        let r = sess.exec(&format!("echo iter-{}", i)).unwrap();
        check!(
            &format!("rapid-fire iter-{} clean", i),
            r.stdout.trim() == format!("iter-{}", i) && !r.stdout.contains("SPAM")
        );
    }

    // 7) Syntax error.
    let r = sess.exec("echo ok && this-cmd-does-not-exist-xyz").unwrap();
    check!("missing cmd → nonzero rc", r.exit_code != 0 && r.stdout.contains("ok"));

    // 8) Unbalanced quotes inside heredoc-wrapped cmd.
    let r = sess.exec("echo \"hi 'there\"").unwrap();
    check!("unbalanced inner quotes", r.stdout.trim() == "hi 'there");

    // 9) Multi-line / semantically bash script.
    let script = r#"
        x=10
        for i in 1 2 3; do
          x=$((x + i))
        done
        echo "result=$x"
    "#;
    let r = sess.exec(script).unwrap();
    check!("multi-line script", r.stdout.trim() == "result=16");

    // 10) State persistence: env var.
    sess.exec("export STATEFUL=42").unwrap();
    let r = sess.exec("echo $STATEFUL").unwrap();
    check!("env persists", r.stdout.trim() == "42");

    // 11) State persistence: cwd.
    sess.exec("mkdir -p subdir && cd subdir && touch marker").unwrap();
    let r = sess.exec("pwd; ls").unwrap();
    check!(
        "cwd & file persist",
        r.stdout.contains("subdir") && r.stdout.contains("marker")
    );
    sess.exec("cd ..").unwrap();

    // 12) Large output (~200 KB) — must not get truncated or corrupted.
    let r = sess.exec("yes payload | head -20000").unwrap();
    let lines: Vec<&str> = r.stdout.lines().collect();
    check!(
        "large output 20k lines intact",
        lines.len() == 20000 && lines.iter().all(|l| *l == "payload")
    );

    // 13) Stderr separation with rogue & still alive.
    let r = sess.exec("echo OUT; echo ERR >&2").unwrap();
    check!(
        "stdout/stderr split",
        r.stdout.trim() == "OUT" && r.stderr.trim() == "ERR"
    );

    // 14) Spawn a slow bg job.
    let t0 = Instant::now();
    let bg1 = sess.spawn("sleep 1.5; echo BG1; echo BG1ERR >&2; exit 3").unwrap();
    check!("spawn returned fast", t0.elapsed() < Duration::from_millis(100));

    // 15) Concurrent exec while bg1 + spam-daemon running.
    let r = sess.exec("echo concurrent").unwrap();
    check!(
        "concurrent exec quick + clean",
        r.stdout.trim() == "concurrent" && !r.stdout.contains("SPAM") && !r.stdout.contains("BG1")
    );

    // 16) Spawn another bg.
    let bg2 = sess.spawn("for i in a b c; do echo $i; sleep 0.3; done").unwrap();
    check!("spawn 2 ok", true);

    // 17) Bunch more execs while two bg jobs run.
    for i in 0..5 {
        let r = sess.exec(&format!("printf 'X{}'", i)).unwrap();
        check!(
            &format!("exec under load #{}", i),
            r.stdout == format!("X{}", i) && !r.stdout.contains("SPAM") && !r.stdout.contains("BG")
        );
    }

    // 18) Wait bg2 first (finishes ~1s).
    let r = bg2.wait().unwrap();
    check!(
        "bg2 captured all 3 lines in order",
        r.stdout == "a\nb\nc\n" && r.exit_code == 0
    );

    // 19) Wait bg1 (~1.5s total).
    let r = bg1.wait().unwrap();
    check!(
        "bg1 stdout/stderr/exit",
        r.stdout.trim() == "BG1" && r.stderr.trim() == "BG1ERR" && r.exit_code == 3
    );

    // 20) Total wall ≈ max(bg1, bg2) not sum.
    check!("wall time ~1.5s (parallel)", t0.elapsed() < Duration::from_millis(2500));

    // 21) Very long single-line output (no newline at end).
    let r = sess.exec("printf '%.0sX' {1..5000}").unwrap();
    check!(
        "5000 chars no trailing newline",
        r.stdout.len() == 5000 && r.stdout.chars().all(|c| c == 'X')
    );

    // 22) Backgrounded subshell with stdout/stderr both noisy AND it doesn't
    //     wait — the next call must still parse.
    sess.exec("(yes corruption; yes more >&2) &").unwrap();
    std::thread::sleep(Duration::from_millis(150));
    let r = sess.exec("echo POST").unwrap();
    check!(
        "post-rogue clean stdout",
        r.stdout.trim() == "POST" && !r.stdout.contains("corruption")
    );
    // Note: the sandbox's FSIZE rlimit may kill the rogue `yes` and bash will
    // print a one-line job-control death notice to its stderr (which is then
    // step N+1's err file). That's the sandbox WORKING (the noise was bounded
    // before reaching us). What we forbid is a flood of raw rogue output
    // leaking through framing — i.e. multiple lines of "corruption"/"more".
    check!(
        "post-rogue stderr not flooded with raw output",
        r.stderr.matches("more").count() <= 1 && r.stderr.matches("corruption").count() <= 1
    );

    // 23) Exit code of `false`.
    let r = sess.exec("false").unwrap();
    check!("false rc=1", r.exit_code == 1);

    // 24) Pipeline exit status (last cmd).
    let r = sess.exec("false | true").unwrap();
    check!("pipeline last rc", r.exit_code == 0);

    // 25) Simulated python-like long compute via spawn.
    let py = sess
        .spawn("for i in 1 2 3; do echo \"py-line-$i\"; sleep 0.4; done; echo py-done")
        .unwrap();
    let r = sess.exec("echo while-py-runs").unwrap();
    check!("exec during py spawn", r.stdout.trim() == "while-py-runs");
    let r = py.wait().unwrap();
    check!(
        "py output intact",
        r.stdout == "py-line-1\npy-line-2\npy-line-3\npy-done\n" && r.exit_code == 0
    );

    sess.close().unwrap();
    println!("\n🎉 ALL {} STEPS PASSED", step);
}
