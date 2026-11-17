//! hn-sandbox: file access that cannot be steered by links, and a keychain.
//!
//! Node has no `openat2`, and `O_NOFOLLOW` is undefined there on Windows, so a check followed by
//! an open can be raced by a local process that swaps a link in between. Every path here is
//! walked one component at a time with each directory held open, and a link, junction or
//! reparse point anywhere on it is refused.
//!
//! The plan names `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`. A component-wise `openat`
//! with `O_NOFOLLOW` gives the same guarantee, because components cannot contain `/` or `..`
//! and each step is relative to a descriptor already held. It also works on macOS and on
//! kernels without `openat2`.

mod box_args;
mod keychain;

#[cfg(windows)]
mod appcontainer;

#[cfg(unix)]
mod fs_unix;
#[cfg(unix)]
use fs_unix as sys;

#[cfg(windows)]
mod fs_windows;
#[cfg(windows)]
use fs_windows as sys;

use std::io::{Read, Write};
use std::process::ExitCode;

/// A refusal or failure, reported as JSON on stderr so the caller can act on `code`.
#[derive(Debug)]
pub struct Fail {
    pub code: &'static str,
    pub message: String,
}

impl Fail {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Fail { code, message: message.into() }
    }
}

pub type Res<T> = Result<T, Fail>;

impl From<std::io::Error> for Fail {
    fn from(error: std::io::Error) -> Self {
        let code = match error.kind() {
            std::io::ErrorKind::NotFound => "not_found",
            std::io::ErrorKind::AlreadyExists => "exists",
            _ => "io",
        };
        Fail::new(code, error.to_string())
    }
}

pub struct WriteOptions {
    pub mkdir: bool,
    pub create_only: bool,
}

const DEFAULT_MAX: u64 = 1 << 20;

#[cfg(windows)]
const RESERVED: [&str; 22] = [
    "con", "prn", "aux", "nul", "conin$", "conout$", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
    "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7",
];

/// Splits a project-relative path into safe components, or says why it is not one.
pub fn split_path(relative: &str) -> Res<Vec<String>> {
    if relative.is_empty() || relative.contains('\0') {
        return Err(Fail::new("outside_root", "the path is empty or contains a NUL"));
    }
    let separators: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
    if relative.starts_with(separators) {
        return Err(Fail::new("outside_root", "absolute paths are not allowed"));
    }
    let mut parts = Vec::new();
    for part in relative.split(separators) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(Fail::new("outside_root", "`..` is not allowed"));
        }
        #[cfg(windows)]
        {
            if part.contains(|c: char| matches!(c, ':' | '<' | '>' | '"' | '|' | '?' | '*') || c.is_control()) {
                return Err(Fail::new("outside_root", format!("{part}: characters Windows treats specially are not allowed")));
            }
            if part.ends_with('.') || part.ends_with(' ') {
                return Err(Fail::new("outside_root", format!("{part}: names ending in a dot or space are not allowed")));
            }
            let stem = part.split('.').next().unwrap_or("").to_lowercase();
            if RESERVED.contains(&stem.as_str()) {
                return Err(Fail::new("outside_root", format!("{part}: reserved device names are not allowed")));
            }
        }
        parts.push(part.to_string());
    }
    if parts.is_empty() {
        return Err(Fail::new("outside_root", "the path names no file"));
    }
    Ok(parts)
}

pub fn json_string(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

struct Args {
    command: String,
    sub: Option<String>,
    values: Vec<(String, String)>,
    flags: Vec<String>,
}

impl Args {
    fn parse() -> Res<Args> {
        let mut raw = std::env::args().skip(1);
        let command = raw.next().ok_or_else(|| Fail::new("usage", "a command is required: read, write, keychain or version"))?;
        let mut args = Args { command, sub: None, values: Vec::new(), flags: Vec::new() };
        let rest: Vec<String> = raw.collect();
        let mut i = 0;
        while i < rest.len() {
            let item = &rest[i];
            if let Some(name) = item.strip_prefix("--") {
                if matches!(name, "mkdir" | "create-only") {
                    args.flags.push(name.to_string());
                } else {
                    let value = rest.get(i + 1).ok_or_else(|| Fail::new("usage", format!("--{name} needs a value")))?;
                    args.values.push((name.to_string(), value.clone()));
                    i += 1;
                }
            } else if args.sub.is_none() {
                args.sub = Some(item.clone());
            } else {
                return Err(Fail::new("usage", format!("unexpected argument {item}")));
            }
            i += 1;
        }
        Ok(args)
    }

    fn value(&self, name: &str) -> Res<&str> {
        self.values
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .ok_or_else(|| Fail::new("usage", format!("--{name} is required")))
    }

    fn max(&self) -> Res<u64> {
        match self.values.iter().find(|(key, _)| key == "max") {
            None => Ok(DEFAULT_MAX),
            Some((_, value)) => value.parse().map_err(|_| Fail::new("usage", "--max must be a number of bytes")),
        }
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|flag| flag == name)
    }
}

fn read_stdin(max: u64) -> Res<Vec<u8>> {
    let mut data = Vec::new();
    std::io::stdin().take(max + 1).read_to_end(&mut data)?;
    if data.len() as u64 > max {
        return Err(Fail::new("too_large", format!("the input is over {max} bytes")));
    }
    Ok(data)
}

fn run() -> Res<()> {
    let args = Args::parse()?;
    match args.command.as_str() {
        "version" => {
            println!("hn-sandbox {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "read" => {
            let parts = split_path(args.value("path")?)?;
            let bytes = sys::read(args.value("root")?, &parts, args.max()?)?;
            std::io::stdout().write_all(&bytes)?;
            Ok(())
        }
        "write" => {
            let parts = split_path(args.value("path")?)?;
            let max = args.max()?;
            let data = read_stdin(max)?;
            let options = WriteOptions { mkdir: args.flag("mkdir"), create_only: args.flag("create-only") };
            let written = sys::write(args.value("root")?, &parts, &data, &options)?;
            println!("{{\"written\":{written}}}");
            Ok(())
        }
        "delete" => {
            let parts = split_path(args.value("path")?)?;
            sys::remove(args.value("root")?, &parts)?;
            println!("{{\"deleted\":true}}");
            Ok(())
        }
        "keychain" => {
            let service = args.value("service")?;
            let account = args.value("account")?;
            match args.sub.as_deref() {
                Some("get") => {
                    std::io::stdout().write_all(&keychain::get(service, account)?)?;
                    Ok(())
                }
                Some("set") => keychain::set(service, account, &read_stdin(2048)?),
                Some("delete") => keychain::delete(service, account),
                _ => Err(Fail::new("usage", "keychain needs get, set or delete")),
            }
        }
        other => Err(Fail::new("usage", format!("unknown command {other}"))),
    }
}

/// `run` and `forget` take their own arguments: `run` passes everything after `--` to the program untouched.
fn box_command(raw: &[String]) -> Option<Res<u32>> {
    match raw.first().map(String::as_str) {
        Some("run") => Some(box_args::parse_run(&raw[1..]).and_then(|spec| run_box(&spec))),
        Some("forget") => Some(match (raw.get(1).map(String::as_str), raw.get(2)) {
            (Some("--name"), Some(name)) => forget_box(name).map(|()| 0),
            _ => Err(Fail::new("usage", "forget needs --name")),
        }),
        _ => None,
    }
}

#[cfg(windows)]
fn run_box(spec: &box_args::RunSpec) -> Res<u32> {
    appcontainer::run(spec)
}

#[cfg(windows)]
fn forget_box(name: &str) -> Res<()> {
    appcontainer::forget(name)
}

#[cfg(not(windows))]
fn run_box(_spec: &box_args::RunSpec) -> Res<u32> {
    Err(Fail::new("unsupported", "the native box in hn-sandbox is Windows only; Linux and macOS use bubblewrap and Seatbelt"))
}

#[cfg(not(windows))]
fn forget_box(_name: &str) -> Res<()> {
    Err(Fail::new("unsupported", "the native box in hn-sandbox is Windows only"))
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if let Some(result) = box_command(&raw) {
        match result {
            // The box's own exit code is passed through whole; Windows codes do not fit in a u8.
            Ok(code) => std::process::exit(code as i32),
            Err(fail) => {
                eprintln!("{{\"code\":\"{}\",\"message\":{}}}", fail.code, json_string(&fail.message));
                // 125 is what a box runner reports for its own failure, apart from any code the program returns.
                std::process::exit(if fail.code == "usage" { 2 } else { 125 });
            }
        }
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(fail) => {
            eprintln!("{{\"code\":\"{}\",\"message\":{}}}", fail.code, json_string(&fail.message));
            ExitCode::from(if fail.code == "usage" { 2 } else { 3 })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_plain_and_mixed_paths() {
        assert_eq!(split_path("a/b/c.txt").unwrap(), ["a", "b", "c.txt"]);
        assert_eq!(split_path("./a//b").unwrap(), ["a", "b"]);
    }

    #[test]
    fn refuses_escapes() {
        for path in ["", "/etc/passwd", "../x", "a/../../x", "a/..", "a\0b"] {
            assert_eq!(split_path(path).unwrap_err().code, "outside_root", "{path}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn refuses_windows_tricks() {
        for path in ["a\\b", "C:\\x", "x:y", "file.txt::$DATA", "name.", "name ", "CON", "dir\\nul.txt", "a\\..\\b", "\\\\server\\share", "q?"] {
            let result = split_path(path);
            if path == "a\\b" {
                assert_eq!(result.unwrap(), ["a", "b"]);
            } else {
                assert!(result.is_err(), "{path}");
            }
        }
    }

    #[test]
    fn json_escapes() {
        assert_eq!(json_string("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
    }
}
