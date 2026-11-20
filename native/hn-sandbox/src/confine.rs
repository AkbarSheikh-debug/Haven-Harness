//! `confine`: the last layers of a Linux box, applied to the process itself just before it runs the command.
//!
//! bubblewrap builds the namespaces and the mounts. This adds what a mount table cannot say:
//! - **Landlock**: a filesystem rule held by the kernel for this process and everything it starts. Reads are allowed
//!   only under the `--read` and `--write` folders, writes only under `--write`. It holds even if a mount is wrong.
//! - **seccomp**: a filter that makes the calls a coding agent never needs (`ptrace`, `mount`, `bpf`, `kexec_load` and
//!   similar) fail with `EPERM`.
//!
//! Neither is assumed. `probe` says what this kernel supports, and a layer that was asked for but is missing is a
//! refusal here (`unavailable`), never a quiet skip, so the caller can report a lower tier instead of claiming one.

use crate::{Fail, Res};

/// What to apply, and the program to run after it.
#[derive(Debug, PartialEq)]
pub struct ConfineSpec {
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub landlock: bool,
    pub seccomp: bool,
    pub program: String,
    pub args: Vec<String>,
}

/// Parses `confine [--landlock] [--seccomp] [--read dir]... [--write dir]... -- program args...`.
pub fn parse_confine(raw: &[String]) -> Res<ConfineSpec> {
    let mut spec = ConfineSpec { read: Vec::new(), write: Vec::new(), landlock: false, seccomp: false, program: String::new(), args: Vec::new() };
    let mut i = 0;
    while i < raw.len() {
        let item = raw[i].as_str();
        match item {
            "--" => {
                let rest = &raw[i + 1..];
                spec.program = rest.first().ok_or_else(|| Fail::new("usage", "confine needs a program after --"))?.clone();
                spec.args = rest[1..].to_vec();
                if !spec.landlock && !spec.seccomp {
                    return Err(Fail::new("usage", "confine needs --landlock or --seccomp, or it applies nothing"));
                }
                if spec.landlock && spec.read.is_empty() && spec.write.is_empty() {
                    return Err(Fail::new("usage", "--landlock needs at least one --read or --write folder, or it would allow nothing at all"));
                }
                return Ok(spec);
            }
            "--landlock" => spec.landlock = true,
            "--seccomp" => spec.seccomp = true,
            "--read" | "--write" => {
                let value = raw.get(i + 1).ok_or_else(|| Fail::new("usage", format!("{item} needs a folder")))?;
                if !value.starts_with('/') {
                    return Err(Fail::new("usage", format!("{item} {value}: folders must be absolute")));
                }
                if item == "--read" { spec.read.push(value.clone()) } else { spec.write.push(value.clone()) }
                i += 1;
            }
            other => return Err(Fail::new("usage", format!("unexpected argument {other}"))),
        }
        i += 1;
    }
    Err(Fail::new("usage", "confine needs -- and a program"))
}

/// What this kernel can apply, as JSON on one line.
pub fn probe_json() -> String {
    let (landlock, seccomp) = probe();
    format!("{{\"landlock_abi\":{landlock},\"seccomp\":{seccomp},\"arch\":\"{}\"}}", std::env::consts::ARCH)
}

#[cfg(target_os = "linux")]
pub use linux::{probe, run};

#[cfg(not(target_os = "linux"))]
pub fn probe() -> (i64, bool) {
    (0, false)
}

#[cfg(not(target_os = "linux"))]
pub fn run(_spec: &ConfineSpec) -> Res<u32> {
    Err(Fail::new("unsupported", "confine is Linux only; macOS uses a Seatbelt profile"))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::ConfineSpec;
    use crate::{Fail, Res};
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    // The kernel's own numbers (linux/landlock.h). The three Landlock calls have the same numbers on every architecture.
    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
    const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
    const CREATE_RULESET_VERSION: libc::c_ulong = 1;
    const RULE_PATH_BENEATH: libc::c_ulong = 1;

    const EXECUTE: u64 = 1 << 0;
    const WRITE_FILE: u64 = 1 << 1;
    const READ_FILE: u64 = 1 << 2;
    const READ_DIR: u64 = 1 << 3;
    const REMOVE_DIR: u64 = 1 << 4;
    const REMOVE_FILE: u64 = 1 << 5;
    const MAKE_CHAR: u64 = 1 << 6;
    const MAKE_DIR: u64 = 1 << 7;
    const MAKE_REG: u64 = 1 << 8;
    const MAKE_SOCK: u64 = 1 << 9;
    const MAKE_FIFO: u64 = 1 << 10;
    const MAKE_BLOCK: u64 = 1 << 11;
    const MAKE_SYM: u64 = 1 << 12;
    const REFER: u64 = 1 << 13; // ABI 2
    const TRUNCATE: u64 = 1 << 14; // ABI 3
    const IOCTL_DEV: u64 = 1 << 15; // ABI 5

    /// Rights that make sense on a file and not only on a folder; a rule on a file may carry nothing else.
    const FILE_RIGHTS: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;
    const READ_RIGHTS: u64 = EXECUTE | READ_FILE | READ_DIR;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        // Network rights (ABI 4). Zero: this box has no network namespace to protect with it, and a zero tail is
        // accepted by every kernel, older or newer, so one struct size works everywhere.
        handled_access_net: u64,
    }

    #[repr(C, packed)]
    struct PathBeneath {
        allowed_access: u64,
        parent_fd: i32,
    }

    fn last_error() -> String {
        std::io::Error::last_os_error().to_string()
    }

    fn landlock_abi() -> i64 {
        // SAFETY: a plain syscall that reads nothing and writes nothing but its result.
        let abi = unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, std::ptr::null::<RulesetAttr>(), 0 as libc::size_t, CREATE_RULESET_VERSION) };
        if abi < 0 { 0 } else { abi as i64 }
    }

    /// `PR_SET_SECCOMP` with no program: `EFAULT` means filters are supported, `EINVAL` means they are not built in.
    fn seccomp_supported() -> bool {
        // SAFETY: a null program pointer is refused by the kernel before it is read.
        let result = unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER as libc::c_ulong, std::ptr::null::<libc::c_void>()) };
        result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EFAULT)
    }

    pub fn probe() -> (i64, bool) {
        (landlock_abi(), seccomp_supported())
    }

    fn handled_rights(abi: i64) -> u64 {
        let mut rights = EXECUTE | WRITE_FILE | READ_FILE | READ_DIR | REMOVE_DIR | REMOVE_FILE | MAKE_CHAR | MAKE_DIR | MAKE_REG | MAKE_SOCK | MAKE_FIFO | MAKE_BLOCK | MAKE_SYM;
        if abi >= 2 {
            rights |= REFER;
        }
        if abi >= 3 {
            rights |= TRUNCATE;
        }
        if abi >= 5 {
            rights |= IOCTL_DEV;
        }
        rights
    }

    /// Every right the kernel handles, for a folder the box may write; reads and the rest follow from it.
    fn write_rights(handled: u64) -> u64 {
        handled
    }

    fn add_path(ruleset: libc::c_int, path: &str, rights: u64, handled: u64) -> Res<()> {
        let c_path = CString::new(std::ffi::OsStr::new(path).as_bytes()).map_err(|_| Fail::new("usage", format!("{path} contains a NUL")))?;
        // SAFETY: c_path is a valid C string; O_PATH opens without reading or writing the target.
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            // A folder the system does not have (/lib32 on many systems) grants nothing, which is what was meant.
            return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(Fail::new("landlock", format!("cannot open {path}: {}", last_error()))) };
        }
        // SAFETY: stat is plain old data and fd is the descriptor just opened.
        let mut info: libc::stat = unsafe { std::mem::zeroed() };
        let is_dir = unsafe { libc::fstat(fd, &mut info) } == 0 && (info.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let mut allowed = rights & handled;
        if !is_dir {
            allowed &= FILE_RIGHTS;
        }
        let rule = PathBeneath { allowed_access: allowed, parent_fd: fd };
        // SAFETY: rule is a valid packed struct of the size the kernel expects, and the descriptors are open.
        let added = unsafe { libc::syscall(SYS_LANDLOCK_ADD_RULE, ruleset as libc::c_long, RULE_PATH_BENEATH, &rule as *const PathBeneath, 0 as libc::c_ulong) };
        let error = last_error();
        // SAFETY: fd was opened above and is closed once.
        unsafe { libc::close(fd) };
        if added < 0 {
            return Err(Fail::new("landlock", format!("cannot add a rule for {path}: {error}")));
        }
        Ok(())
    }

    fn apply_landlock(spec: &ConfineSpec) -> Res<()> {
        let abi = landlock_abi();
        if abi < 1 {
            return Err(Fail::new("unavailable", "this kernel does not have Landlock enabled"));
        }
        let handled = handled_rights(abi);
        let attr = RulesetAttr { handled_access_fs: handled, handled_access_net: 0 };
        // SAFETY: attr is a valid struct of the size passed.
        let ruleset = unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, &attr as *const RulesetAttr, std::mem::size_of::<RulesetAttr>() as libc::size_t, 0 as libc::c_ulong) };
        if ruleset < 0 {
            return Err(Fail::new("landlock", format!("cannot create a ruleset: {}", last_error())));
        }
        let ruleset = ruleset as libc::c_int;
        for dir in &spec.read {
            add_path(ruleset, dir, READ_RIGHTS, handled)?;
        }
        for dir in &spec.write {
            add_path(ruleset, dir, write_rights(handled), handled)?;
        }
        // The devices a shell needs (null, zero, urandom, tty): read and write on files there, nothing that creates or removes.
        add_path(ruleset, "/dev", READ_FILE | WRITE_FILE | READ_DIR | TRUNCATE | IOCTL_DEV, handled)?;
        // SAFETY: a plain prctl with constant arguments.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) } != 0 {
            return Err(Fail::new("landlock", format!("cannot set no_new_privs: {}", last_error())));
        }
        // SAFETY: the ruleset descriptor is valid; after this the process is confined for good.
        let restricted = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset as libc::c_long, 0 as libc::c_ulong) };
        let error = last_error();
        // SAFETY: closed once.
        unsafe { libc::close(ruleset) };
        if restricted < 0 {
            return Err(Fail::new("landlock", format!("cannot restrict this process: {error}")));
        }
        Ok(())
    }

    /// The calls a coding agent never needs, and that open a way out of the box or into the host kernel.
    pub fn denied_syscalls() -> Vec<(&'static str, i64)> {
        let mut calls: Vec<(&'static str, i64)> = vec![
            ("ptrace", libc::SYS_ptrace),
            ("process_vm_readv", libc::SYS_process_vm_readv),
            ("process_vm_writev", libc::SYS_process_vm_writev),
            ("mount", libc::SYS_mount),
            ("umount2", libc::SYS_umount2),
            ("pivot_root", libc::SYS_pivot_root),
            ("kexec_load", libc::SYS_kexec_load),
            ("bpf", libc::SYS_bpf),
            ("init_module", libc::SYS_init_module),
            ("finit_module", libc::SYS_finit_module),
            ("delete_module", libc::SYS_delete_module),
            ("reboot", libc::SYS_reboot),
            ("swapon", libc::SYS_swapon),
            ("swapoff", libc::SYS_swapoff),
            ("acct", libc::SYS_acct),
            ("perf_event_open", libc::SYS_perf_event_open),
            ("userfaultfd", libc::SYS_userfaultfd),
            ("keyctl", libc::SYS_keyctl),
            ("add_key", libc::SYS_add_key),
            ("request_key", libc::SYS_request_key),
            ("open_by_handle_at", libc::SYS_open_by_handle_at),
            ("quotactl", libc::SYS_quotactl),
            ("setns", libc::SYS_setns),
            ("unshare", libc::SYS_unshare),
            ("settimeofday", libc::SYS_settimeofday),
            ("clock_settime", libc::SYS_clock_settime),
            ("adjtimex", libc::SYS_adjtimex),
            ("clock_adjtime", libc::SYS_clock_adjtime),
            // The newer mount API, which is the same set of numbers on every architecture.
            ("open_tree", 428),
            ("move_mount", 429),
            ("fsopen", 430),
            ("fsconfig", 431),
            ("fsmount", 432),
            ("fspick", 433),
            ("mount_setattr", 442),
        ];
        #[cfg(target_arch = "x86_64")]
        {
            calls.push(("kexec_file_load", libc::SYS_kexec_file_load));
            calls.push(("iopl", libc::SYS_iopl));
            calls.push(("ioperm", libc::SYS_ioperm));
        }
        #[cfg(target_arch = "aarch64")]
        {
            calls.push(("kexec_file_load", libc::SYS_kexec_file_load));
        }
        calls
    }

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xC000_00B7;

    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JEQ_K: u16 = 0x15;
    const BPF_JGE_K: u16 = 0x35;
    const BPF_RET_K: u16 = 0x06;
    const RET_ALLOW: u32 = 0x7fff_0000;
    const RET_KILL_PROCESS: u32 = 0x8000_0000;
    const RET_ERRNO: u32 = 0x0005_0000;

    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter { code, jt: 0, jf: 0, k }
    }

    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    /// The filter: a call from another architecture ends the process (so no 32-bit or x32 door past the list), a listed
    /// call fails with EPERM, everything else runs.
    pub fn build_filter(calls: &[(&'static str, i64)]) -> Vec<libc::sock_filter> {
        let mut program = vec![
            stmt(BPF_LD_W_ABS, 4), // seccomp_data.arch
            jump(BPF_JEQ_K, AUDIT_ARCH, 1, 0),
            stmt(BPF_RET_K, RET_KILL_PROCESS),
            stmt(BPF_LD_W_ABS, 0), // seccomp_data.nr
        ];
        #[cfg(target_arch = "x86_64")]
        {
            // x32 calls are the same architecture with this bit set; none of them is ever needed.
            program.push(jump(BPF_JGE_K, 0x4000_0000, 0, 1));
            program.push(stmt(BPF_RET_K, RET_KILL_PROCESS));
        }
        let count = calls.len();
        for (index, (_, number)) in calls.iter().enumerate() {
            // A match jumps over the remaining compares and the allow, to the EPERM at the end.
            program.push(jump(BPF_JEQ_K, *number as u32, (count - index) as u8, 0));
        }
        program.push(stmt(BPF_RET_K, RET_ALLOW));
        program.push(stmt(BPF_RET_K, RET_ERRNO | libc::EPERM as u32));
        program
    }

    fn apply_seccomp() -> Res<()> {
        if !seccomp_supported() {
            return Err(Fail::new("unavailable", "this kernel does not have seccomp filters"));
        }
        let mut filter = build_filter(&denied_syscalls());
        let program = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
        // SAFETY: a plain prctl with constant arguments.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) } != 0 {
            return Err(Fail::new("seccomp", format!("cannot set no_new_privs: {}", last_error())));
        }
        // SAFETY: program points at a valid filter that outlives the call; the kernel copies it.
        if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER as libc::c_ulong, &program as *const libc::sock_fprog) } != 0 {
            return Err(Fail::new("seccomp", format!("cannot install the filter: {}", last_error())));
        }
        Ok(())
    }

    /// Applies the layers, then replaces this process with the program. Returns only if the program could not start.
    pub fn run(spec: &ConfineSpec) -> Res<u32> {
        if spec.landlock {
            apply_landlock(spec)?;
        }
        if spec.seccomp {
            apply_seccomp()?;
        }
        let error = Command::new(&spec.program).args(&spec.args).exec();
        Err(Fail::new("exec", format!("cannot start {}: {error}", spec.program)))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_filter_denies_what_it_lists_and_ends_a_foreign_architecture() {
            let calls = denied_syscalls();
            let program = build_filter(&calls);
            // arch load, arch check, kill, nr load, (x32 check and kill on x86_64), one compare per call, allow, deny.
            let fixed = if cfg!(target_arch = "x86_64") { 6 } else { 4 };
            assert_eq!(program.len(), fixed + calls.len() + 2);
            let deny_at = program.len() - 1;
            for (index, entry) in program.iter().enumerate().skip(fixed).take(calls.len()) {
                assert_eq!(index + 1 + entry.jt as usize, deny_at, "a compare at {index} must land on the EPERM return");
            }
            assert_eq!(program[deny_at].k, RET_ERRNO | libc::EPERM as u32);
            assert_eq!(program[deny_at - 1].k, RET_ALLOW);
        }

        #[test]
        fn nothing_a_build_needs_is_denied() {
            let names: Vec<&str> = denied_syscalls().iter().map(|(name, _)| *name).collect();
            for needed in ["read", "write", "openat", "execve", "clone", "clone3", "fork", "mmap", "futex", "socket", "connect", "getdents64", "prlimit64", "memfd_create", "io_uring_setup"] {
                assert!(!names.contains(&needed), "{needed} must stay allowed");
            }
            for denied in ["ptrace", "mount", "kexec_load", "bpf", "setns", "unshare"] {
                assert!(names.contains(&denied), "{denied} must be denied");
            }
        }

        #[test]
        fn every_denied_number_is_distinct() {
            let calls = denied_syscalls();
            let mut numbers: Vec<i64> = calls.iter().map(|(_, number)| *number).collect();
            numbers.sort_unstable();
            numbers.dedup();
            assert_eq!(numbers.len(), calls.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn parses_layers_folders_and_the_program() {
        let spec = parse_confine(&args(&["--landlock", "--seccomp", "--read", "/usr", "--write", "/work", "--", "sh", "-c", "echo hi"])).unwrap();
        assert!(spec.landlock && spec.seccomp);
        assert_eq!(spec.read, ["/usr"]);
        assert_eq!(spec.write, ["/work"]);
        assert_eq!(spec.program, "sh");
        assert_eq!(spec.args, ["-c", "echo hi"]);
    }

    #[test]
    fn the_programs_own_flags_are_never_read_as_ours() {
        let spec = parse_confine(&args(&["--seccomp", "--", "ls", "--landlock", "--write", "x"])).unwrap();
        assert_eq!(spec.args, ["--landlock", "--write", "x"]);
        assert!(!spec.landlock);
    }

    #[test]
    fn refuses_a_confine_that_would_apply_nothing_or_allow_nothing() {
        for bad in [
            args(&["--", "sh"]),
            args(&["--landlock", "--", "sh"]),
            args(&["--seccomp"]),
            args(&["--seccomp", "--"]),
            args(&["--seccomp", "--read", "relative", "--", "sh"]),
            args(&["--seccomp", "--bogus", "--", "sh"]),
            args(&["--seccomp", "--write"]),
        ] {
            assert_eq!(parse_confine(&bad).unwrap_err().code, "usage", "{bad:?}");
        }
    }

    #[test]
    fn probe_is_one_line_of_json() {
        let json = probe_json();
        assert!(json.starts_with("{\"landlock_abi\":") && json.contains("\"seccomp\":") && !json.contains('\n'), "{json}");
    }
}
