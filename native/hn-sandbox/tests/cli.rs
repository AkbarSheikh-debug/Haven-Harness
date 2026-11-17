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
