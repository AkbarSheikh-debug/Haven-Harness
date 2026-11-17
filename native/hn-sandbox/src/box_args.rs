//! The `run` command's arguments, and the Windows command-line quoting the box needs.
//! Kept apart from the Windows code so it is tested on every platform.

use crate::{Fail, Res};

/// What to start in a box, and what the box may touch.
#[derive(Debug, PartialEq)]
pub struct RunSpec {
    /// The AppContainer profile name. One per session, so two sessions never share a SID.
    pub name: String,
    /// Folders the box may read and write (its copy of the project, its HOME and TEMP).
    pub grants: Vec<String>,
    /// Folders the box may only read and run from.
    pub reads: Vec<String>,
    /// Folders the box may see the names in and pass through, but nothing below them (no inheritance).
    /// Some programs (PowerShell) refuse to start in a folder whose parents they cannot open.
    pub lists: Vec<String>,
    pub cwd: String,
    /// The whole environment of the box. Nothing is inherited from the caller.
    pub env: Vec<(String, String)>,
    pub memory: Option<u64>,
    pub processes: Option<u32>,
    /// Where to write what the started process's token and job really are, read back from Windows.
    pub report: Option<String>,
    pub program: String,
    pub args: Vec<String>,
}

const MAX_PROCESSES: u32 = 4096;

/// Parses `run --name n --grant d --read d --cwd d --env K=V --memory b --processes n --report f -- program args...`.
pub fn parse_run(raw: &[String]) -> Res<RunSpec> {
    let mut spec = RunSpec {
        name: String::new(),
        grants: Vec::new(),
        reads: Vec::new(),
        lists: Vec::new(),
        cwd: String::new(),
        env: Vec::new(),
        memory: None,
        processes: None,
        report: None,
        program: String::new(),
        args: Vec::new(),
    };
    let mut i = 0;
    while i < raw.len() {
        let item = raw[i].as_str();
        if item == "--" {
            let rest = &raw[i + 1..];
            let program = rest.first().ok_or_else(|| Fail::new("usage", "run needs a program after --"))?;
            spec.program = program.clone();
            spec.args = rest[1..].to_vec();
            break;
        }
        let name = item.strip_prefix("--").ok_or_else(|| Fail::new("usage", format!("unexpected argument {item}")))?;
        let value = raw.get(i + 1).ok_or_else(|| Fail::new("usage", format!("--{name} needs a value")))?.clone();
        match name {
            "name" => spec.name = value,
            "grant" => spec.grants.push(value),
            "read" => spec.reads.push(value),
            "list" => spec.lists.push(value),
            "cwd" => spec.cwd = value,
            "report" => spec.report = Some(value),
            "env" => {
                let (key, val) = value.split_once('=').ok_or_else(|| Fail::new("usage", "--env takes KEY=VALUE"))?;
                if key.is_empty() || key.contains('\0') || val.contains('\0') {
                    return Err(Fail::new("usage", "--env takes KEY=VALUE with no NUL"));
                }
                spec.env.push((key.to_string(), val.to_string()));
            }
            "memory" => spec.memory = Some(value.parse().map_err(|_| Fail::new("usage", "--memory is a number of bytes"))?),
            "processes" => {
                let count: u32 = value.parse().map_err(|_| Fail::new("usage", "--processes is a number"))?;
                if count == 0 || count > MAX_PROCESSES {
                    return Err(Fail::new("usage", format!("--processes must be 1 to {MAX_PROCESSES}")));
                }
                spec.processes = Some(count);
            }
            other => return Err(Fail::new("usage", format!("run does not take --{other}"))),
        }
        i += 2;
    }
    if spec.program.is_empty() {
        return Err(Fail::new("usage", "run needs -- and a program"));
    }
    // A profile name becomes part of a SID and a registry key, so only a plain name is accepted.
    if spec.name.is_empty() || spec.name.len() > 64 || !spec.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return Err(Fail::new("usage", "--name must be 1 to 64 letters, digits, dots or dashes"));
    }
    if spec.cwd.is_empty() {
        return Err(Fail::new("usage", "--cwd is required"));
    }
    for path in spec.grants.iter().chain(spec.reads.iter()).chain(spec.lists.iter()).chain(std::iter::once(&spec.cwd)).chain(std::iter::once(&spec.program)) {
        if !is_absolute(path) {
            return Err(Fail::new("usage", format!("{path} is not an absolute path")));
        }
    }
    // A grant on a drive root or a top-level folder would rewrite permissions across a whole drive.
    for path in spec.grants.iter().chain(spec.reads.iter()).chain(spec.lists.iter()) {
        if depth(path) < 2 {
            return Err(Fail::new("usage", format!("{path} is too near the root of a drive to grant to a box")));
        }
    }
    Ok(spec)
}

/// How many folders deep a path is: `C:\` is 0, `C:\a` is 1.
fn depth(path: &str) -> usize {
    path.split(['/', '\\']).skip(1).filter(|part| !part.is_empty() && *part != ".").count()
}

/// Absolute with a drive letter (or `/` on Unix). A bare name could be found in the current folder.
fn is_absolute(path: &str) -> bool {
    if cfg!(windows) {
        let bytes = path.as_bytes();
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/')
    } else {
        path.starts_with('/')
    }
}

/// Quotes one argument the way libuv does, so a command reaches the shell in the box exactly as it
/// reaches the shell on the host (Node starts the local shell with libuv's rules).
pub fn quote_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// The full command line: the program, then every argument quoted.
pub fn command_line(program: &str, args: &[String]) -> String {
    let mut line = quote_arg(program);
    for arg in args {
        line.push(' ');
        line.push_str(&quote_arg(arg));
    }
    line
}

/// A Unicode environment block, sorted by name ignoring case as Windows expects.
pub fn env_block(env: &[(String, String)]) -> Vec<u16> {
    let mut pairs: Vec<&(String, String)> = env.iter().collect();
    pairs.sort_by_key(|(key, _)| key.to_uppercase());
    let mut block: Vec<u16> = Vec::new();
    for (key, value) in pairs {
        block.extend(format!("{key}={value}").encode_utf16());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[cfg(windows)]
    #[test]
    fn parses_a_full_run() {
        let spec = parse_run(&strings(&[
            "--name", "hn.box.a1", "--grant", "C:\\hn\\box", "--read", "C:\\tools\\bin", "--cwd", "C:\\hn\\box\\work", "--env", "A=b=c", "--memory", "1024",
            "--processes", "8", "--report", "C:\\hn\\r.json", "--", "C:\\bin\\bash.exe", "-c", "echo hi",
        ]))
        .unwrap();
        assert_eq!(spec.grants, ["C:\\hn\\box"]);
        assert!(parse_run(&strings(&["--name", "x", "--cwd", "C:\\hn\\w", "--grant", "C:\\hn", "--", "C:\\bin\\x.exe"])).is_err());
        assert!(parse_run(&strings(&["--name", "x", "--cwd", "C:\\hn\\w", "--list", "D:\\", "--", "C:\\bin\\x.exe"])).is_err());
        assert_eq!(spec.env, [("A".to_string(), "b=c".to_string())]);
        assert_eq!(spec.memory, Some(1024));
        assert_eq!(spec.processes, Some(8));
        assert_eq!(spec.program, "C:\\bin\\bash.exe");
        assert_eq!(spec.args, ["-c", "echo hi"]);
    }

    #[test]
    fn refuses_bad_runs() {
        for raw in [
            vec!["--name", "x", "--cwd", "/w"],
            vec!["--name", "bad name", "--cwd", "/w", "--", "/bin/sh"],
            vec!["--name", "x", "--", "/bin/sh"],
            vec!["--name", "x", "--cwd", "/w", "--processes", "0", "--", "/bin/sh"],
            vec!["--name", "x", "--cwd", "/w", "--env", "NOEQUALS", "--", "/bin/sh"],
            vec!["--name", "x", "--cwd", "/w", "--net", "on", "--", "/bin/sh"],
            vec!["--name", "x", "--cwd", "/w", "--", "sh"],
            vec!["--name", "x", "--cwd", "/w/a", "--grant", "/w", "--", "/bin/sh"],
            vec!["--name", "x", "--cwd", "/w/a", "--list", "/", "--", "/bin/sh"],
        ] {
            assert!(parse_run(&strings(&raw)).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn quotes_like_libuv() {
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("a b"), "\"a b\"");
        assert_eq!(quote_arg("say \"hi\""), "\"say \\\"hi\\\"\"");
        assert_eq!(quote_arg("dir\\ with\\"), "\"dir\\ with\\\\\"");
        assert_eq!(quote_arg("a\\\"b c"), "\"a\\\\\\\"b c\"");
        assert_eq!(command_line("C:\\x y\\p.exe", &strings(&["-c", "echo 1"])), "\"C:\\x y\\p.exe\" -c \"echo 1\"");
    }

    #[test]
    fn builds_a_sorted_block() {
        let block = env_block(&[("b".into(), "2".into()), ("A".into(), "1".into())]);
        let text = String::from_utf16(&block).unwrap();
        assert_eq!(text, "A=1\0b=2\0\0");
        assert_eq!(String::from_utf16(&env_block(&[])).unwrap(), "\0\0");
    }
}
