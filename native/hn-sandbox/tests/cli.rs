use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

const BIN: &str = env!("CARGO_BIN_EXE_hn-sandbox");

struct Out {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

impl Out {
    fn error_code(&self) -> String {
        let marker = "\"code\":\"";
        let start = self.stderr.find(marker).map(|i| i + marker.len()).unwrap_or(0);
        self.stderr[start..].split('"').next().unwrap_or("").to_string()
    }
}

fn run(args: &[&str], stdin: &[u8]) -> Out {
    let mut child = Command::new(BIN).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let output = child.wait_with_output().unwrap();
    Out { code: output.status.code().unwrap_or(-1), stdout: output.stdout, stderr: String::from_utf8_lossy(&output.stderr).to_string() }
}

fn read(root: &Path, path: &str) -> Out {
    run(&["read", "--root", root.to_str().unwrap(), "--path", path], b"")
}

fn write(root: &Path, path: &str, data: &[u8], extra: &[&str]) -> Out {
    let mut args = vec!["write", "--root", root.to_str().unwrap(), "--path", path];
    args.extend_from_slice(extra);
    run(&args, data)
}

/// A scratch folder with a `project` and an `outside` next to each other, removed when dropped.
struct Scratch {
    base: PathBuf,
    project: PathBuf,
    outside: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        let base = std::env::temp_dir().join(format!("hn-sandbox-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let base = {
            fs::create_dir_all(&base).unwrap();
            fs::canonicalize(&base).unwrap()
        };
        // canonicalize on Windows returns a \\?\ path; the helper wants the ordinary form.
        let plain = |p: PathBuf| PathBuf::from(p.to_string_lossy().trim_start_matches(r"\\?\").to_string());
        let base = plain(base);
        let project = base.join("project");
        let outside = base.join("outside");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), "TOP SECRET").unwrap();
        Scratch { base, project, outside }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// A directory link: a junction on Windows (no privilege needed), a symlink elsewhere.
fn link_dir(link: &Path, target: &Path) {
    #[cfg(windows)]
    {
        let status = Command::new("cmd").args(["/C", "mklink", "/J", link.to_str().unwrap(), target.to_str().unwrap()]).stdout(Stdio::null()).status().unwrap();
        assert!(status.success(), "mklink /J failed");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
}

fn unlink_dir(link: &Path) {
    #[cfg(windows)]
    let _ = fs::remove_dir(link);
    #[cfg(unix)]
    let _ = fs::remove_file(link);
}

#[test]
fn reads_a_file_inside_the_root() {
    let s = Scratch::new("read");
    fs::create_dir_all(s.project.join("a/b")).unwrap();
    fs::write(s.project.join("a/b/c.txt"), "hello").unwrap();
    let out = read(&s.project, "a/b/c.txt");
    assert_eq!((out.code, out.stdout), (0, b"hello".to_vec()));
    assert_eq!(read(&s.project, "./a//b/c.txt").stdout, b"hello");
}

#[test]
fn refuses_to_leave_the_root() {
    let s = Scratch::new("escape");
    for path in ["../outside/secret.txt", "a/../../outside/secret.txt", "/etc/passwd", ""] {
        let out = read(&s.project, path);
        assert_eq!((out.code, out.error_code().as_str()), (3, "outside_root"), "{path}");
    }
}

#[test]
fn refuses_a_link_as_a_folder_on_the_path() {
    let s = Scratch::new("linkdir");
    link_dir(&s.project.join("sub"), &s.outside);
    let out = read(&s.project, "sub/secret.txt");
    assert_eq!(out.error_code(), "link");
    assert!(out.stdout.is_empty());
    let out = write(&s.project, "sub/new.txt", b"x", &[]);
    assert_eq!(out.error_code(), "link");
    assert!(!s.outside.join("new.txt").exists(), "the write went through the link");
    let out = write(&s.project, "sub/deeper/new.txt", b"x", &["--mkdir"]);
    assert_eq!(out.error_code(), "link");
    assert!(!s.outside.join("deeper").exists(), "mkdir went through the link");
}

#[cfg(unix)]
#[test]
fn refuses_a_symlink_as_the_file_itself() {
    let s = Scratch::new("linkfile");
    std::os::unix::fs::symlink(s.outside.join("secret.txt"), s.project.join("note.txt")).unwrap();
    assert_eq!(read(&s.project, "note.txt").error_code(), "link");
    assert_eq!(write(&s.project, "note.txt", b"x", &[]).error_code(), "link");
    assert_eq!(fs::read_to_string(s.outside.join("secret.txt")).unwrap(), "TOP SECRET");
}

#[test]
fn refuses_a_file_with_more_than_one_name() {
    let s = Scratch::new("hardlink");
    fs::hard_link(s.outside.join("secret.txt"), s.project.join("innocent.txt")).unwrap();
    let out = read(&s.project, "innocent.txt");
    assert_eq!((out.code, out.error_code().as_str()), (3, "hardlink"));
    assert!(out.stdout.is_empty());
    assert_eq!(write(&s.project, "innocent.txt", b"x", &[]).error_code(), "hardlink");
    assert_eq!(fs::read_to_string(s.outside.join("secret.txt")).unwrap(), "TOP SECRET");
}

#[test]
fn refuses_directories_and_oversize_files() {
    let s = Scratch::new("kinds");
    fs::create_dir_all(s.project.join("dir")).unwrap();
    assert_eq!(read(&s.project, "dir").error_code(), "not_regular");
    fs::write(s.project.join("big.bin"), vec![b'x'; 5000]).unwrap();
    let out = run(&["read", "--root", s.project.to_str().unwrap(), "--path", "big.bin", "--max", "100"], b"");
    assert_eq!(out.error_code(), "too_large");
    assert_eq!(read(&s.project, "missing.txt").error_code(), "not_found");
}

#[test]
fn writes_create_replace_and_leave_nothing_behind() {
    let s = Scratch::new("write");
    let out = write(&s.project, "a/b/new.txt", b"one", &["--mkdir"]);
    assert_eq!((out.code, out.stdout.as_slice()), (0, b"{\"written\":3}\n".as_slice()));
    assert_eq!(fs::read_to_string(s.project.join("a/b/new.txt")).unwrap(), "one");
    assert_eq!(write(&s.project, "a/b/new.txt", b"two", &[]).code, 0);
    assert_eq!(fs::read_to_string(s.project.join("a/b/new.txt")).unwrap(), "two");
    let names: Vec<String> = fs::read_dir(s.project.join("a/b")).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    assert_eq!(names, ["new.txt"], "a temp file was left behind");
}

#[test]
fn write_without_mkdir_does_not_create_folders() {
    let s = Scratch::new("nomkdir");
    assert_eq!(write(&s.project, "missing/dir/x.txt", b"x", &[]).error_code(), "not_found");
    assert!(!s.project.join("missing").exists());
}

#[test]
fn create_only_never_replaces() {
    let s = Scratch::new("createonly");
    assert_eq!(write(&s.project, "once.txt", b"first", &["--create-only"]).code, 0);
    assert_eq!(write(&s.project, "once.txt", b"second", &["--create-only"]).error_code(), "exists");
    assert_eq!(fs::read_to_string(s.project.join("once.txt")).unwrap(), "first");
}

#[test]
fn input_over_the_limit_is_refused_before_anything_is_written() {
    let s = Scratch::new("limit");
    let out = run(&["write", "--root", s.project.to_str().unwrap(), "--path", "x.txt", "--max", "4"], b"too long for that");
    assert_eq!(out.error_code(), "too_large");
    assert!(!s.project.join("x.txt").exists());
}

#[test]
fn attack_swapping_a_folder_for_a_link_during_reads_never_leaks() {
    let s = Scratch::new("race");
    let real = s.project.join("sub");
    fs::create_dir_all(&real).unwrap();
    fs::write(real.join("secret.txt"), "harmless inside").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let flips = Arc::new(AtomicUsize::new(0));
    let flipper = {
        let (stop, flips, sub, outside, holding) = (stop.clone(), flips.clone(), real.clone(), s.outside.clone(), s.project.join("sub-real"));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                // Move the real folder away and put a link to the outside in its place, then undo it.
                if fs::rename(&sub, &holding).is_ok() {
                    link_dir(&sub, &outside);
                    flips.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    unlink_dir(&sub);
                    let _ = fs::rename(&holding, &sub);
                }
            }
        })
    };
    let mut leaked = false;
    for _ in 0..150 {
        let out = read(&s.project, "sub/secret.txt");
        if out.stdout == b"TOP SECRET" {
            leaked = true;
        }
    }
    stop.store(true, Ordering::Relaxed);
    flipper.join().unwrap();
    assert!(flips.load(Ordering::Relaxed) > 0, "the folder was never swapped, so this test proved nothing");
    assert!(!leaked, "the helper returned a file from outside the project");
}

#[test]
fn usage_errors_exit_with_2_and_version_works() {
    assert_eq!(run(&[], b"").code, 2);
    assert_eq!(run(&["read"], b"").code, 2);
    assert_eq!(run(&["frobnicate"], b"").code, 2);
    let out = run(&["version"], b"");
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("hn-sandbox "));
}

#[cfg(windows)]
#[test]
fn keychain_round_trips_and_forgets() {
    let service = format!("hn-sandbox-test-{}", std::process::id());
    let base = ["keychain"];
    let with = |sub: &str| {
        let mut args = base.to_vec();
        args.push(sub);
        args.extend_from_slice(&["--service", &service, "--account", "tester"]);
        args.iter().map(|s| s.to_string()).collect::<Vec<_>>()
    };
    let call = |sub: &str, stdin: &[u8]| {
        let owned = with(sub);
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        run(&refs, stdin)
    };
    assert_eq!(call("set", b"not-a-real-key-123").code, 0);
    let got = call("get", b"");
    assert_eq!((got.code, got.stdout), (0, b"not-a-real-key-123".to_vec()));
    assert_eq!(call("delete", b"").code, 0);
    assert_eq!(call("get", b"").error_code(), "not_found");
}

fn delete(root: &Path, path: &str) -> Out {
    run(&["delete", "--root", root.to_str().unwrap(), "--path", path], b"")
}

#[test]
fn deletes_a_regular_file_and_nothing_else() {
    let s = Scratch::new("delete");
    fs::create_dir_all(s.project.join("a")).unwrap();
    fs::write(s.project.join("a/x.txt"), "x").unwrap();
    fs::write(s.project.join("a/y.txt"), "y").unwrap();
    assert_eq!(delete(&s.project, "a/x.txt").code, 0);
    assert!(!s.project.join("a/x.txt").exists());
    assert!(s.project.join("a/y.txt").exists());
    assert_eq!(delete(&s.project, "a/x.txt").error_code(), "not_found");
}

#[test]
fn delete_refuses_directories_and_escapes() {
    let s = Scratch::new("deldir");
    fs::create_dir_all(s.project.join("dir")).unwrap();
    assert_eq!(delete(&s.project, "dir").error_code(), "not_regular");
    assert!(s.project.join("dir").exists());
    assert_eq!(delete(&s.project, "../outside/secret.txt").error_code(), "outside_root");
    assert!(s.outside.join("secret.txt").exists());
}

#[test]
fn delete_does_not_go_through_a_link() {
    let s = Scratch::new("dellink");
    link_dir(&s.project.join("sub"), &s.outside);
    let out = delete(&s.project, "sub/secret.txt");
    assert_eq!((out.code, out.error_code().as_str()), (3, "link"));
    assert!(s.outside.join("secret.txt").exists(), "the file outside was deleted through the link");
}

/// Landlock and seccomp are the kernel's, so these run against the real kernel, on Linux only. A layer the kernel does not
/// have is skipped here by saying so; the box code reports such a box as a lower tier and never claims the layer.
#[cfg(target_os = "linux")]
mod confine {
    use super::*;

    const SYSTEM: [&str; 6] = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"];

    fn probe() -> (i64, bool) {
        let out = run(&["probe"], b"");
        assert_eq!(out.code, 0, "{}", out.stderr);
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let abi = text.split("\"landlock_abi\":").nth(1).unwrap().split(',').next().unwrap().parse().unwrap();
        (abi, text.contains("\"seccomp\":true"))
    }

    fn confined(layers: &[&str], extra: &[&str], command: &str) -> Out {
        let mut args: Vec<&str> = vec!["confine"];
        args.extend_from_slice(layers);
        for dir in SYSTEM {
            args.extend(["--read", dir]);
        }
        args.extend_from_slice(extra);
        args.extend(["--", "sh", "-c", command]);
        run(&args, b"")
    }

    #[test]
    fn probe_says_what_the_kernel_can_do() {
        let (abi, _) = probe();
        assert!(abi >= 0);
    }

    #[test]
    fn landlock_stops_a_write_outside_the_allowed_folder_and_a_read_of_a_secret() {
        let (abi, _) = probe();
        if abi < 1 {
            eprintln!("skipped: this kernel has no Landlock");
            return;
        }
        let scratch = Scratch::new("landlock");
        fs::write(scratch.outside.join("secret.txt"), "host secret").unwrap();
        let project = scratch.project.to_str().unwrap();
        let outside = scratch.outside.to_str().unwrap();

        // Control: with no confine at all, the same command writes outside and reads the secret.
        let plain = Command::new("sh").args(["-c", &format!("echo x > {outside}/plain.txt")]).status().unwrap();
        assert!(plain.success());
        assert!(scratch.outside.join("plain.txt").exists());

        let wrote = confined(&["--landlock"], &["--write", project], &format!("echo x > {outside}/escape.txt"));
        assert_ne!(wrote.code, 0, "a write outside the allowed folder must fail");
        assert!(!scratch.outside.join("escape.txt").exists(), "the file outside was created");

        let read = confined(&["--landlock"], &["--write", project], &format!("cat {outside}/secret.txt"));
        assert_ne!(read.code, 0);
        assert!(!String::from_utf8_lossy(&read.stdout).contains("host secret"));

        let inside = confined(&["--landlock"], &["--write", project], &format!("echo ok > {project}/made.txt && mkdir {project}/d && cat {project}/made.txt"));
        assert_eq!(inside.code, 0, "{}", inside.stderr);
        assert!(String::from_utf8_lossy(&inside.stdout).contains("ok"));

        // A folder granted read-only cannot be written.
        let readonly = confined(&["--landlock"], &["--write", project, "--read", outside], &format!("echo x > {outside}/ro.txt"));
        assert_ne!(readonly.code, 0);
        assert!(!scratch.outside.join("ro.txt").exists());
    }

    #[test]
    fn landlock_covers_what_a_mount_table_would_not_a_rename_into_and_out_of_the_folder() {
        let (abi, _) = probe();
        if abi < 1 {
            return;
        }
        let scratch = Scratch::new("landlock-rename");
        fs::write(scratch.outside.join("victim.txt"), "keep").unwrap();
        let project = scratch.project.to_str().unwrap();
        let outside = scratch.outside.to_str().unwrap();
        let moved = confined(&["--landlock"], &["--write", project], &format!("mv {outside}/victim.txt {project}/victim.txt"));
        assert_ne!(moved.code, 0, "moving a file out of a folder the box may not write must fail");
        assert_eq!(fs::read_to_string(scratch.outside.join("victim.txt")).unwrap(), "keep");
        let removed = confined(&["--landlock"], &["--write", project], &format!("rm {outside}/victim.txt"));
        assert_ne!(removed.code, 0);
        assert!(scratch.outside.join("victim.txt").exists());
    }

    #[test]
    fn a_layer_that_was_asked_for_and_is_missing_is_refused_never_skipped() {
        let (abi, seccomp) = probe();
        let scratch = Scratch::new("missing");
        let project = scratch.project.to_str().unwrap();
        if abi < 1 {
            let out = confined(&["--landlock"], &["--write", project], "true");
            assert_eq!(out.error_code(), "unavailable");
            assert_eq!(out.code, 125);
        }
        if !seccomp {
            let out = confined(&["--seccomp"], &[], "true");
            assert_eq!(out.error_code(), "unavailable");
        }
    }

    /// `ptrace` with a request no kernel knows: the kernel answers EIO when it is allowed to look, so EPERM can only be the filter.
    const PTRACE: &str = r#"perl -e 'use Errno; $r = syscall(%PTRACE%, -1, 0, 0, 0); print(($!+0), "\n")'"#;

    fn ptrace_number() -> &'static str {
        if cfg!(target_arch = "x86_64") { "101" } else { "117" }
    }

    #[test]
    fn seccomp_makes_the_listed_calls_fail_and_leaves_ordinary_work_alone() {
        let (_, seccomp) = probe();
        if !seccomp {
            eprintln!("skipped: this kernel has no seccomp filters");
            return;
        }
        if Command::new("perl").arg("-e").arg("1").status().map(|status| status.success()).unwrap_or(false) == false {
            eprintln!("skipped: perl is not installed, so no raw system call can be made");
            return;
        }
        let command = PTRACE.replace("%PTRACE%", ptrace_number());
        let free = Command::new("sh").args(["-c", &command]).output().unwrap();
        assert_ne!(String::from_utf8_lossy(&free.stdout).trim(), "1", "without the filter ptrace must not answer EPERM; the check proves nothing");

        let filtered = confined(&["--seccomp"], &[], &command);
        assert_eq!(String::from_utf8_lossy(&filtered.stdout).trim(), "1", "ptrace must fail with EPERM inside the filter: {}", filtered.stderr);

        // An ordinary build step still works under the filter: files, processes, pipes, a compiler-ish workload.
        let work = confined(&["--seccomp"], &[], "mkdir -p /tmp/hn-seccomp-$$ && cd /tmp/hn-seccomp-$$ && echo a > f && cat f | tr a b | tee g && ls | wc -l && rm -rf /tmp/hn-seccomp-$$");
        assert_eq!(work.code, 0, "{}", work.stderr);
        assert!(String::from_utf8_lossy(&work.stdout).contains('b'));
    }
}
