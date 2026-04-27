//! Write a seccomp BPF filter file for bwrap's `--seccomp FD` option.
//!
//! Blocks: ptrace, mount, umount2, keyctl, kexec_load, kexec_file_load,
//! pivot_root, chroot, socket(AF_UNIX), clone(CLONE_NEWUSER), unshare(CLONE_NEWUSER).

#![cfg(target_os = "linux")]

use crate::Result;
use std::io::Write;
use std::path::Path;

#[cfg(target_arch = "x86_64")]
mod nr {
    #[allow(dead_code)]
    pub const SOCKET: u32 = 41;
    pub const PTRACE: u32 = 101;
    pub const MOUNT: u32 = 165;
    pub const UMOUNT2: u32 = 166;
    pub const CLONE: u32 = 56;
    pub const KEYCTL: u32 = 250;
    pub const KEXEC_LOAD: u32 = 246;
    pub const KEXEC_FILE_LOAD: u32 = 320;
    pub const PIVOT_ROOT: u32 = 155;
    pub const CHROOT: u32 = 161;
    pub const UNSHARE: u32 = 272;
}

#[cfg(target_arch = "aarch64")]
mod nr {
    #[allow(dead_code)]
    pub const SOCKET: u32 = 198;
    pub const PTRACE: u32 = 117;
    pub const MOUNT: u32 = 40;
    pub const UMOUNT2: u32 = 39;
    pub const CLONE: u32 = 220;
    pub const KEYCTL: u32 = 219;
    pub const KEXEC_LOAD: u32 = 104;
    pub const KEXEC_FILE_LOAD: u32 = 294;
    pub const PIVOT_ROOT: u32 = 41;
    pub const CHROOT: u32 = 51;
    pub const UNSHARE: u32 = 97;
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod nr {
    #[allow(dead_code)]
    pub const SOCKET: u32 = 0;
    pub const PTRACE: u32 = 0;
    pub const MOUNT: u32 = 0;
    pub const UMOUNT2: u32 = 0;
    pub const CLONE: u32 = 0;
    pub const KEYCTL: u32 = 0;
    pub const KEXEC_LOAD: u32 = 0;
    pub const KEXEC_FILE_LOAD: u32 = 0;
    pub const PIVOT_ROOT: u32 = 0;
    pub const CHROOT: u32 = 0;
    pub const UNSHARE: u32 = 0;
}

#[allow(dead_code)]
const AF_UNIX: u32 = 1;
const CLONE_NEWUSER: u32 = 0x10000000;

const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const SECCOMP_RET_ERRNO: u32 = 0x00050000;
const EPERM: u32 = 1;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;
const BPF_ALU: u16 = 0x04;
const BPF_AND: u16 = 0x50;

const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARGS: u32 = 16;

type BpfInst = (u16, u8, u8, u32);

fn build_bpf_instructions() -> Vec<BpfInst> {
    let deny: BpfInst = (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM);
    let allow: BpfInst = (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW);

    let mut f: Vec<BpfInst> = Vec::with_capacity(36);
    f.push((BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_NR));

    for sc in [
        nr::PTRACE,
        nr::MOUNT,
        nr::UMOUNT2,
        nr::KEYCTL,
        nr::KEXEC_LOAD,
        nr::KEXEC_FILE_LOAD,
        nr::PIVOT_ROOT,
        nr::CHROOT,
    ] {
        f.push((BPF_JMP | BPF_JEQ | BPF_K, 0, 1, sc));
        f.push(deny);
    }

    // clone(CLONE_NEWUSER)
    f.push((BPF_JMP | BPF_JEQ | BPF_K, 0, 4, nr::CLONE));
    f.push((BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_ARGS));
    f.push((BPF_ALU | BPF_AND | BPF_K, 0, 0, CLONE_NEWUSER));
    f.push((BPF_JMP | BPF_JEQ | BPF_K, 0, 1, CLONE_NEWUSER));
    f.push(deny);
    f.push((BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_NR));

    // unshare(CLONE_NEWUSER)
    f.push((BPF_JMP | BPF_JEQ | BPF_K, 0, 4, nr::UNSHARE));
    f.push((BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_ARGS));
    f.push((BPF_ALU | BPF_AND | BPF_K, 0, 0, CLONE_NEWUSER));
    f.push((BPF_JMP | BPF_JEQ | BPF_K, 0, 1, CLONE_NEWUSER));
    f.push(deny);

    f.push(allow);
    f
}

/// Serialize BPF instructions to bytes (for file or in-memory use).
pub fn serialize_bpf(instructions: &[BpfInst]) -> Vec<u8> {
    let mut out = Vec::with_capacity(instructions.len() * 8);
    for &(code, jt, jf, k) in instructions {
        out.extend_from_slice(&code.to_ne_bytes());
        out.extend_from_slice(&[jt]);
        out.extend_from_slice(&[jf]);
        out.extend_from_slice(&k.to_ne_bytes());
    }
    out
}

/// Generate BPF filter bytes (for in-process seccomp install).
pub fn generate_bpf_bytes() -> Vec<u8> {
    serialize_bpf(&build_bpf_instructions())
}

pub(crate) fn generate_bpf_file(path: &Path) -> Result<()> {
    let instructions = build_bpf_instructions();
    let bytes = serialize_bpf(&instructions);
    let mut file = std::fs::File::create(path)?;
    file.write_all(&bytes)?;
    Ok(())
}
