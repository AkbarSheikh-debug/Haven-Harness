//! Unix: the path is walked with `openat`, one component at a time, each opened `O_NOFOLLOW`
//! and relative to a directory descriptor already held. A symlink anywhere on the path fails
//! with ELOOP, and a swap between steps cannot redirect a later step because it is relative to
//! the descriptor, not the name.

use crate::{Fail, Res, WriteOptions};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};

struct Fd(RawFd);

impl Drop for Fd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn map(error: std::io::Error) -> Fail {
    match error.raw_os_error() {
        Some(libc::ELOOP) => Fail::new("link", "a symbolic link is not allowed in the path"),
        Some(libc::ENOTDIR) => Fail::new("not_directory", "a part of the path is not a directory"),
        Some(libc::EXDEV) => Fail::new("outside_root", "the path leaves the project root"),
        _ => error.into(),
    }
}

fn last_error() -> Fail {
    map(std::io::Error::last_os_error())
}

fn cstring(text: &str) -> Res<CString> {
    CString::new(text).map_err(|_| Fail::new("outside_root", "the path contains a NUL"))
}

fn open_root(root: &str) -> Res<Fd> {
    let path = cstring(root)?;
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(last_error());
    }
    Ok(Fd(fd))
}

fn open_dir_at(parent: RawFd, name: &str) -> Res<Fd> {
    let path = cstring(name)?;
    let fd = unsafe { libc::openat(parent, path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        // Linux reports a symlinked folder as ENOTDIR, not ELOOP, so look at what the name really is.
        if matches!(error.raw_os_error(), Some(libc::ENOTDIR) | Some(libc::ELOOP)) {
            let mut info: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatat(parent, path.as_ptr(), &mut info, libc::AT_SYMLINK_NOFOLLOW) } == 0 && info.st_mode & libc::S_IFMT == libc::S_IFLNK {
                return Err(Fail::new("link", format!("{name} is a symbolic link")));
            }
        }
        return Err(map(error));
    }
    Ok(Fd(fd))
}

/// Opens every directory on the way down and returns the last one, which holds the file.
fn walk(root: &str, dirs: &[String], mkdir: bool) -> Res<Vec<Fd>> {
    let mut held = vec![open_root(root)?];
    for dir in dirs {
        let parent = held.last().map(|fd| fd.0).unwrap_or(-1);
        if mkdir {
            let path = cstring(dir)?;
            if unsafe { libc::mkdirat(parent, path.as_ptr(), 0o755) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(map(error));
                }
            }
        }
        held.push(open_dir_at(parent, dir)?);
    }
    Ok(held)
}

fn stat_fd(fd: RawFd) -> Res<libc::stat> {
    let mut info: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut info) } != 0 {
        return Err(last_error());
    }
    Ok(info)
}

/// A target must be a plain file nobody else links to.
fn check_regular(info: &libc::stat, name: &str) -> Res<()> {
    let kind = info.st_mode & libc::S_IFMT;
    if kind == libc::S_IFLNK {
        return Err(Fail::new("link", format!("{name} is a symbolic link")));
    }
    if kind != libc::S_IFREG {
        return Err(Fail::new("not_regular", format!("{name} is not a regular file")));
    }
    if info.st_nlink as u64 != 1 {
        return Err(Fail::new("hardlink", format!("{name} has more than one name, so it may be a way into another file")));
    }
    Ok(())
}

pub fn read(root: &str, parts: &[String], max: u64) -> Res<Vec<u8>> {
    let (name, dirs) = parts.split_last().ok_or_else(|| Fail::new("outside_root", "the path names no file"))?;
    let held = walk(root, dirs, false)?;
    let parent = held.last().map(|fd| fd.0).unwrap_or(-1);
    let path = cstring(name)?;
    // O_NONBLOCK so a FIFO planted in the project cannot hang the read.
    let fd = unsafe { libc::openat(parent, path.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if fd < 0 {
        return Err(last_error());
    }
    let info = stat_fd(fd)?;
    let mut file = unsafe { File::from_raw_fd(fd) };
    check_regular(&info, name)?;
    if info.st_size as u64 > max {
        return Err(Fail::new("too_large", format!("{name} is over {max} bytes")));
    }
    let mut data = Vec::new();
    (&mut file).take(max + 1).read_to_end(&mut data)?;
    if data.len() as u64 > max {
        return Err(Fail::new("too_large", format!("{name} grew past {max} bytes while it was read")));
    }
    Ok(data)
}

pub fn write(root: &str, parts: &[String], data: &[u8], options: &WriteOptions) -> Res<u64> {
    let (name, dirs) = parts.split_last().ok_or_else(|| Fail::new("outside_root", "the path names no file"))?;
    let held = walk(root, dirs, options.mkdir)?;
    let parent = held.last().map(|fd| fd.0).unwrap_or(-1);
    let target = cstring(name)?;

    let mut existing_mode: Option<libc::mode_t> = None;
    let mut info: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, target.as_ptr(), &mut info, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
        check_regular(&info, name)?;
        if options.create_only {
            return Err(Fail::new("exists", format!("{name} already exists")));
        }
        existing_mode = Some(info.st_mode & 0o777);
    } else {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOENT) {
            return Err(map(error));
        }
    }

    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let temp_name = format!(".hn-tmp-{}-{nanos}", std::process::id());
    let temp = cstring(&temp_name)?;
    let fd = unsafe { libc::openat(parent, temp.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
    if fd < 0 {
        return Err(last_error());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let cleanup = || unsafe {
        libc::unlinkat(parent, temp.as_ptr(), 0);
    };
    if let Err(error) = file.write_all(data) {
        cleanup();
        return Err(error.into());
    }
    if let Some(mode) = existing_mode {
        unsafe { libc::fchmod(fd, mode) };
    }
    if let Err(error) = file.sync_all() {
        cleanup();
        return Err(error.into());
    }
    drop(file);

    let moved = if options.create_only {
        // linkat fails if the name appeared in the meantime, where rename would replace it.
        let result = unsafe { libc::linkat(parent, temp.as_ptr(), parent, target.as_ptr(), 0) };
        cleanup();
        result
    } else {
        unsafe { libc::renameat(parent, temp.as_ptr(), parent, target.as_ptr()) }
    };
    if moved != 0 {
        let error = std::io::Error::last_os_error();
        cleanup();
        return Err(if error.raw_os_error() == Some(libc::EEXIST) { Fail::new("exists", format!("{name} already exists")) } else { map(error) });
    }
    unsafe { libc::fsync(parent) };
    Ok(data.len() as u64)
}

/// Removes one regular file. Directories and links are refused, so a hand-back cannot delete through one.
pub fn remove(root: &str, parts: &[String]) -> Res<()> {
    let (name, dirs) = parts.split_last().ok_or_else(|| Fail::new("outside_root", "the path names no file"))?;
    let held = walk(root, dirs, false)?;
    let parent = held.last().map(|fd| fd.0).unwrap_or(-1);
    let target = cstring(name)?;
    let mut info: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, target.as_ptr(), &mut info, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(last_error());
    }
    match info.st_mode & libc::S_IFMT {
        libc::S_IFLNK => return Err(Fail::new("link", format!("{name} is a symbolic link"))),
        libc::S_IFREG => {}
        _ => return Err(Fail::new("not_regular", format!("{name} is not a regular file"))),
    }
    if unsafe { libc::unlinkat(parent, target.as_ptr(), 0) } != 0 {
        return Err(last_error());
    }
    Ok(())
}
