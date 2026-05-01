# PTY API -- Cross-Platform Interactive Terminal

## Context

The user needs SSH-like interactive terminal access to sandbox VMs (for xterm.js + WebSocket frontend). This requires PTY (pseudo-terminal) support, which provides: combined stdin/stdout over a single channel, terminal escape codes (colors, cursor), signal handling (Ctrl-C), terminal resize, and job control.

Current state: Linux PTY works via SCM_RIGHTS (host gets master fd). macOS returns `not_implemented`. Windows has PTY fields in the protocol but no host-side implementation. The init-side PTY relay for stream transports (macOS/Windows) is already fully implemented in `server.rs:1362-1398`.

Goal: Add `PtyHandle` type and `Sandbox::open_pty()` method that works on all 3 platforms. WebSocket server is out of scope -- the user will wire that up themselves using `PtyHandle`'s `Read + Write + resize()` interface.

---

## Step 1: New type `PtyHandle` in `src/api.rs`

```rust
/// Interactive PTY session handle. Implements Read (stdout) + Write (stdin).
/// Platform-agnostic: on Linux wraps the raw master fd; on macOS/Windows
/// bridges through the init protocol.
pub struct PtyHandle {
    child_id: String,
    job_id: JobId,
    // Writer declared before reader -- drops first (closes stdin -> child exits
    // -> reader drains remaining output -> EOF).
    writer: Box<dyn std::io::Write + Send>,
    reader: Box<dyn std::io::Read + Send>,
    resize_fn: Box<dyn Fn(u16, u16) -> Result<()> + Send>,
}
```

Methods:
- `pub fn child_id(&self) -> &str`
- `pub fn job_id(&self) -> &JobId`
- `pub fn resize(&self, rows: u16, cols: u16) -> Result<()>`
- `impl Read for PtyHandle` (delegates to reader)
- `impl Write for PtyHandle` (delegates to writer)

Re-export `PtyHandle` from `src/lib.rs`.

## Step 2: Backend trait (`src/backend.rs`)

Add:
```rust
fn open_pty(&self, argv: &[String], opts: ExecOpts) -> Result<PtyHandle>;
```

## Step 3: Linux backend (`src/linux/sandbox.rs`)

`InitClient::spawn_pty()` already returns `(SpawnInfo, OwnedFd)` via SCM_RIGHTS.

1. Clone `init_client` Arc, allocate job ID (same pattern as existing `spawn()`)
2. `client.spawn_pty(&argv_refs, &opts.env, cwd, opts.pty_rows, opts.pty_cols)`
3. Store `JobSpawnInfo { child_id, pty_fd: Some(fd) }` in jobs map + child_to_job
4. Build PtyHandle:
   - `writer`: `File::from(master_fd)` (takes ownership)
   - `reader`: `File::from(nix::unistd::dup(&master_fd)?)` (dup for independent read end)
   - `resize_fn`: closure calling `client.resize(&child_id, rows, cols)`

No event pump changes -- Linux PTY children don't emit Stdout/Stderr events (host owns master fd).

## Step 4: macOS init client (`src/macos/vsock_init_client.rs`)

### 4a. Fix `spawn_pty` (line 200-211)

Change from returning `not_implemented` to sending `Op::Spawn { stdio: StdioMode::Pty { rows, cols } }` via existing `spawn_ack()`. Return `Result<SpawnInfo>` (no fd -- VSOCK can't pass fds). Init-side stream-bridged PTY relay already handles the rest.

### 4b. Add `InitStdin` adapter

Port pattern from `src/windows/init_client.rs:595-614`:
```rust
pub(crate) struct InitStdin {
    client: Arc<VsockInitClient>,
    child_id: String,
}
impl Write for InitStdin { ... }  // calls client.write()
```

### 4c. Add `InitReader` adapter

Port pattern from `src/windows/init_client.rs:630-725`:
```rust
pub(crate) struct InitReader {
    client: Arc<VsockInitClient>,
    child_id: String,
    leftover: Vec<u8>,
}
impl Read for InitReader { ... }  // blocks on Condvar, drains per-child stdout chunks
```

Both adapters need access to `VsockInitClient.inner.state`. Add `pub(crate)` accessor:
```rust
impl VsockInitClient {
    pub(crate) fn shared_state(&self) -> &Arc<(Mutex<Shared>, Condvar)> {
        &self.inner.state
    }
}
```

## Step 5: macOS event pump fix (`src/macos/sandbox.rs`)

Problem: `event_pump_loop` (line 517) drains ALL children's stdout/stderr. For PTY children, `InitReader` must consume those events instead.

1. Add `pty_children: Arc<Mutex<HashSet<String>>>` to `RunningState`
2. Pass to `event_pump_loop` as parameter
3. In the loop, skip stdout/stderr drain for child_ids in `pty_children` (still process Exit events)
4. In `open_pty`, insert child_id into `pty_children` BEFORE calling `spawn_pty` to prevent race

## Step 6: macOS backend (`src/macos/sandbox.rs`)

Implement `MacosBackend::open_pty`:

1. Get `init: Arc<VsockInitClient>` from state
2. Insert child_id into `pty_children` exclusion set
3. `init.spawn_pty(argv, env, cwd, rows, cols)` -> `SpawnInfo`
4. Register in `child_to_job` map
5. Build PtyHandle with `InitReader`/`InitStdin` + resize closure calling `init.resize()`

## Step 7: Windows service protocol (`src/svc_protocol.rs`)

### 7a. Add resize method
```rust
// in method module:
pub const RESIZE: &str = "resize";

// params struct:
#[derive(Serialize, Deserialize)]
pub struct ResizeParams {
    pub id: String,
    pub child_id: String,
    pub rows: u16,
    pub cols: u16,
}
```

### 7b. Service handler (`src/bin/tokimo-sandbox-svc/`)

Handle `method::RESIZE`: deserialize `ResizeParams`, call `WinInitClient::resize(&params.child_id, params.rows, params.cols)`, return ack.

Also verify PTY spawn path: `ExecParams` already has `pty`/`pty_rows`/`pty_cols` fields. Ensure the service's spawn handler forwards these as `StdioMode::Pty` to `WinInitClient`. If it currently only calls `spawn_pipes`, add a `spawn_pty` branch.

## Step 8: Windows backend (`src/windows/sandbox.rs`)

Implement `WindowsBackend::open_pty`:

1. Call SPAWN JSON-RPC with `pty: true, pty_rows, pty_cols` -> `SpawnResult { id: child_id }`
2. Build PtyHandle:
   - `reader`: custom `Read` impl using `subscribe()` -> `mpsc::Receiver<Event>`. Filter for `Event::Stdout` matching child_id. Return EOF on matching `Event::Exit`. Each subscribe() gets its own channel copy -- no stealing from other subscribers.
   - `writer`: custom `Write` impl calling `self.call(method::WRITE_STDIN, WriteStdinParams { id, child_id, data_b64 })`
   - `resize_fn`: closure calling `self.call(method::RESIZE, ResizeParams { id, child_id, rows, cols })`

## Step 9: Public API (`src/api.rs`)

```rust
pub fn open_pty<S: AsRef<str>>(&self, cmd: &[S], opts: ExecOpts) -> Result<PtyHandle> {
    let argv: Vec<String> = cmd.iter().map(|s| s.as_ref().to_owned()).collect();
    if argv.is_empty() {
        return Err(Error::validation("empty argv"));
    }
    self.inner.open_pty(&argv, opts)
}
```

---

## Implementation order

1. `src/api.rs` -- PtyHandle type
2. `src/backend.rs` -- open_pty trait method
3. `src/linux/sandbox.rs` -- Linux open_pty
4. `src/macos/vsock_init_client.rs` -- fix spawn_pty + add InitReader/InitStdin
5. `src/macos/sandbox.rs` -- event pump fix + open_pty
6. `src/svc_protocol.rs` -- resize method
7. `src/bin/tokimo-sandbox-svc/` -- resize handler + PTY spawn forwarding
8. `src/windows/sandbox.rs` -- Windows open_pty
9. `src/api.rs` -- Sandbox::open_pty public method
10. `src/lib.rs` -- re-export PtyHandle

## Verification

1. `cargo build` compiles on all targets
2. `cargo test --lib` -- existing tests pass
3. Linux: `open_pty(&["bash"], opts)` -> interactive shell via Read/Write
4. `pty_handle.resize(50, 120)` -> `stty size` inside guest shows `50 120`
5. xterm.js integration: user builds WS bridge using `PtyHandle` as the I/O layer

## Usage example (what the user will build on top)

```rust
let sb = Sandbox::connect().unwrap();
sb.configure(ConfigureParams { ... }).unwrap();
sb.start_vm().unwrap();

let mut pty = sb.open_pty(&["bash"], ExecOpts {
    pty_rows: 24,
    pty_cols: 80,
    ..Default::default()
}).unwrap();

// In WS handler: read from pty -> send to WS, receive from WS -> write to pty
// On terminal resize: pty.resize(rows, cols)
```
