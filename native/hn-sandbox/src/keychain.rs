//! The OS credential store, so a key does not have to live in a file a same-user process can read.
//! Windows is implemented here. macOS Keychain and the Linux Secret Service report `unsupported`,
//! and the caller falls back to the key file until they are added.

use crate::{Fail, Res};

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    };

    const ERROR_NOT_FOUND: i32 = 1168;

    fn wide(text: &str) -> Vec<u16> {
        OsStr::new(text).encode_wide().chain(std::iter::once(0)).collect()
    }

    fn target(service: &str, account: &str) -> Vec<u16> {
        wide(&format!("{service}/{account}"))
    }

    fn failure() -> Fail {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_NOT_FOUND) {
            Fail::new("not_found", "no such credential")
        } else {
            Fail::new("io", error.to_string())
        }
    }

    pub fn get(service: &str, account: &str) -> Res<Vec<u8>> {
        let name = target(service, account);
        let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
        if unsafe { CredReadW(name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } == 0 {
            return Err(failure());
        }
        let blob = unsafe {
            let entry = &*credential;
            std::slice::from_raw_parts(entry.CredentialBlob, entry.CredentialBlobSize as usize).to_vec()
        };
        unsafe { CredFree(credential as *const _) };
        Ok(blob)
    }

    pub fn set(service: &str, account: &str, value: &[u8]) -> Res<()> {
        let name = target(service, account);
        let user = wide(account);
        let mut credential: CREDENTIALW = unsafe { std::mem::zeroed() };
        credential.Type = CRED_TYPE_GENERIC;
        credential.TargetName = name.as_ptr() as *mut u16;
        credential.UserName = user.as_ptr() as *mut u16;
        credential.CredentialBlobSize = value.len() as u32;
        credential.CredentialBlob = value.as_ptr() as *mut u8;
        credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
        if unsafe { CredWriteW(&credential, 0) } == 0 {
            return Err(failure());
        }
        Ok(())
    }

    pub fn delete(service: &str, account: &str) -> Res<()> {
        let name = target(service, account);
        if unsafe { CredDeleteW(name.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            return Err(failure());
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    fn unsupported<T>() -> Res<T> {
        Err(Fail::new("unsupported", "this platform has no keychain backend yet; use the key file"))
    }

    pub fn get(_service: &str, _account: &str) -> Res<Vec<u8>> {
        unsupported()
    }
    pub fn set(_service: &str, _account: &str, _value: &[u8]) -> Res<()> {
        unsupported()
    }
    pub fn delete(_service: &str, _account: &str) -> Res<()> {
        unsupported()
    }
}

pub use imp::{delete, get, set};
