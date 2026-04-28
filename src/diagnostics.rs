//! Helpers for classifying error messages produced by the sandbox.

/// Classify whether an error message indicates the underlying sandbox
/// session is dead and the slot should be rebuilt.
///
/// **Important contract**: callers that emit a per-command timeout (e.g.
/// `"command timed out after Xms; killed"`) must NOT match this list —
/// the session is fine in that case; only the runaway user command was
/// killed. Only true session-level deaths (broken pipe, exec timeout
/// teardown, poisoned state) should flip a "dead" flag.
pub fn is_session_fatal_message(msg: &str) -> bool {
    msg.contains("Broken pipe")
        || msg.contains("session is closed")
        || msg.contains("session shell exited")
        || msg.contains("session terminated")
        || msg.contains("session state poisoned")
        // Defense-in-depth: `Session::exec` (legacy path) timeout calls
        // `close_inner()` which kills the bwrap process tree. Higher
        // layers may have moved to spawn + kill_job, but this substring
        // stays as a safety net. `init_client::run_oneshot` uses the
        // distinct phrase "init op N timed out" and does NOT tear down
        // the session, so it correctly does not match.
        || msg.contains("exec timed out")
}

#[cfg(test)]
mod tests {
    use super::is_session_fatal_message;

    #[test]
    fn detects_exec_timeout_as_fatal() {
        // Real error string from `Session::exec` timeout teardown:
        // session.rs:419 `"session exec timed out after {:?}"`.
        // Wrapped by `AgentSandbox::exec` as `"Session::exec: <inner>"`.
        // Must match so the manager rebuilds the dead sandbox.
        assert!(is_session_fatal_message(
            "Session::exec: session exec timed out after 5s"
        ));
    }

    #[test]
    fn detects_classic_fatal_patterns() {
        assert!(is_session_fatal_message("Broken pipe (os error 32)"));
        assert!(is_session_fatal_message("session is closed"));
        assert!(is_session_fatal_message("session shell exited with status 1"));
        assert!(is_session_fatal_message("session terminated"));
        assert!(is_session_fatal_message("session state poisoned"));
    }

    #[test]
    fn ignores_init_oneshot_timeout() {
        // `init_client::run_oneshot` timeout — does NOT tear down the
        // session, so it must not flip the dead flag. The init timeout
        // string format is `"init op {id} timed out"` — no `"exec timed out"`
        // substring, so our match correctly skips it.
        assert!(!is_session_fatal_message("init op 42 timed out"));
    }

    #[test]
    fn ignores_unrelated_errors() {
        assert!(!is_session_fatal_message("command not found"));
        assert!(!is_session_fatal_message("permission denied"));
        assert!(!is_session_fatal_message("exit code 1"));
    }
}
