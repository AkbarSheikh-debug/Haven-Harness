//! Windows: every directory on the path is opened without delete-sharing and kept open, so it
//! cannot be renamed, deleted or swapped for a junction while the operation runs. Each object is
//! opened with FILE_FLAG_OPEN_REPARSE_POINT, so a link is seen as a link instead of followed.

use crate::{Fail, Res, WriteOptions};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, GetFinalPathNameByHandleW, MoveFileExW, BY_HANDLE_FILE_INFORMATION, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH,
};

const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// Others may read and write, but may not delete or rename while we hold it.
const SHARE_READ_WRITE: u32 = 0x1 | 0x2;

fn wide(path: &Path) -> Vec<u16> {
    OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect()
}

fn open_dir(path: &Path) -> Res<File> {
    let dir = OpenOptions::new()
        .read(true)
        .share_mode(SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let attributes = dir.metadata()?.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Fail::new("link", format!("{} is a link or junction", path.display())));
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(Fail::new("not_directory", format!("{} is not a directory", path.display())));
    }
    Ok(dir)
}

fn link_count(file: &File) -> Res<u32> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(info.nNumberOfLinks)
}

fn final_path(file: &File) -> Res<String> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut buffer = vec![0u16; 1024];
    loop {
        let length = unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) } as usize;
        if length == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if length < buffer.len() {
            buffer.truncate(length);
            let text = String::from_utf16_lossy(&buffer);
            return Ok(text.strip_prefix(r"\\?\").unwrap_or(&text).to_string());
        }
        buffer.resize(length + 1, 0);
    }
}

/// An existing target must be a plain file nobody else links to.
fn check_regular(file: &File, shown: &Path) -> Res<()> {
    let attributes = file.metadata()?.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Fail::new("link", format!("{} is a link", shown.display())));
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(Fail::new("not_regular", format!("{} is a directory", shown.display())));
    }
    if link_count(file)? != 1 {
        return Err(Fail::new("hardlink", format!("{} has more than one name, so it may be a way into another file", shown.display())));
    }
    Ok(())
}

fn open_existing(path: &Path) -> std::io::Result<File> {
    // Backup semantics lets a directory open too, so it is reported as not a regular file instead of as a vague I/O error.
    OpenOptions::new()
        .read(true)
        .share_mode(SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

fn held_dirs(root: &str, dirs: &[String], mkdir: bool) -> Res<(Vec<File>, PathBuf, String)> {
    let mut path = PathBuf::from(root);
    let root_dir = open_dir(&path)?;
    let root_final = final_path(&root_dir)?;
    let mut held = vec![root_dir];
    for dir in dirs {
        path.push(dir);
        if mkdir {
            match std::fs::create_dir(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        held.push(open_dir(&path)?);
    }
    Ok((held, path, root_final))
}

fn inside(file: &File, root_final: &str) -> Res<()> {
    let actual = final_path(file)?.to_lowercase();
    let mut prefix = root_final.to_lowercase();
    if !prefix.ends_with('\\') {
        prefix.push('\\');
    }
    if actual.starts_with(&prefix) {
        Ok(())
    } else {
        Err(Fail::new("outside_root", "the file is not under the project root"))
    }
}

pub fn read(root: &str, parts: &[String], max: u64) -> Res<Vec<u8>> {
    let (name, dirs) = parts.split_last().ok_or_else(|| Fail::new("outside_root", "the path names no file"))?;
    let (held, mut path, root_final) = held_dirs(root, dirs, false)?;
    path.push(name);
    let file = open_existing(&path)?;
    check_regular(&file, &path)?;
    inside(&file, &root_final)?;
    if file.metadata()?.len() > max {
        return Err(Fail::new("too_large", format!("{} is over {max} bytes", path.display())));
    }
    let mut data = Vec::new();
    (&file).take(max + 1).read_to_end(&mut data)?;
    drop(held);
    if data.len() as u64 > max {
        return Err(Fail::new("too_large", format!("{} grew past {max} bytes while it was read", path.display())));
    }
    Ok(data)
}

pub fn write(root: &str, parts: &[String], data: &[u8], options: &WriteOptions) -> Res<u64> {
    let (name, dirs) = parts.split_last().ok_or_else(|| Fail::new("outside_root", "the path names no file"))?;
    let (held, parent, _root_final) = held_dirs(root, dirs, options.mkdir)?;
    let target = parent.join(name);

    match open_existing(&target) {
        Ok(existing) => {
            check_regular(&existing, &target)?;
            if options.create_only {
                return Err(Fail::new("exists", format!("{} already exists", target.display())));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let temp = parent.join(format!(".hn-tmp-{}-{nanos}", std::process::id()));
    let mut file = OpenOptions::new().write(true).create_new(true).share_mode(0).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(&temp)?;
    let written = file.write_all(data).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(error.into());
    }

    let flags = MOVEFILE_WRITE_THROUGH | if options.create_only { 0 } else { MOVEFILE_REPLACE_EXISTING };
    let moved = unsafe { MoveFileExW(wide(&temp).as_ptr(), wide(&target).as_ptr(), flags) };
    drop(held);
    if moved == 0 {
        let error = std::io::Error::last_os_error();
        let _ = std::fs::remove_file(&temp);
        return Err(if options.create_only && target.exists() { Fail::new("exists", format!("{} already exists", target.display())) } else { error.into() });
    }
    Ok(data.len() as u64)
}

/// Removes one regular file. Directories and links are refused, so a hand-back cannot delete through one.
pub fn remove(root: &str, parts: &[String]) -> Res<()> {
    let (name, dirs) = parts.split_last().ok_or_else(|| Fail::new("outside_root", "the path names no file"))?;
    let (held, parent, _root_final) = held_dirs(root, dirs, false)?;
    let target = parent.join(name);
    {
        let file = open_existing(&target)?;
        let attributes = file.metadata()?.file_attributes();
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Fail::new("link", format!("{} is a link", target.display())));
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(Fail::new("not_regular", format!("{} is a directory", target.display())));
        }
    }
    std::fs::remove_file(&target)?;
    drop(held);
    Ok(())
}
