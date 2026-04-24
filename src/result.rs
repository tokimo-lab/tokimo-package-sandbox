/// Result of running a command inside the sandbox.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    /// Process exit code, or -1 if the process was killed by the sandbox.
    pub exit_code: i32,
    /// True if the sandbox killed the process due to timeout.
    pub timed_out: bool,
    /// True if the sandbox killed the process due to memory overrun.
    pub oom_killed: bool,
}

impl ExecutionResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0 && !self.timed_out && !self.oom_killed
    }
}
