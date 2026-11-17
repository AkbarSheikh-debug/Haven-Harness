//! The Windows native box: an AppContainer with no capabilities, inside a Job Object.
//!
//! - No capabilities means no `internetClient`, no `privateNetworkClientServer` and no loopback,
//!   so the box has no network at all. Whether that holds is proved from outside by the caller's
//!   canary, never taken from this code's word.
//! - An AppContainer token opens a file only when its ACL names the container's SID (or ALL
//!   APPLICATION PACKAGES, which Windows gives to system folders such as Program Files). The user's
//!   home, the host project and every other drive are closed to it. This code grants the SID only
//!   the folders it is told to.
//! - The Job Object kills every process in the box when this helper exits, caps how many may run
//!   and how much memory they may use, and keeps them off the clipboard and other desktops.
//! - Only the three standard handles are inherited, so nothing else the caller holds leaks in.

use crate::box_args::{command_line, env_block, RunSpec};
use crate::{json_string, Fail, Res};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE,
    SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName};
use windows_sys::Win32::Security::{
    FreeSid, InitializeSecurityDescriptor, SetFileSecurityW, SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SECURITY_DESCRIPTOR,
    SE_DACL_AUTO_INHERITED, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenCapabilities, TokenIntegrityLevel, TokenIsAppContainer, ACL,
    DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_CAPABILITIES, SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_TRAVERSE, SYNCHRONIZE,
};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
    JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess, InitializeProcThreadAttributeList, OpenProcessToken, ResumeThread,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

const ALREADY_EXISTS: i32 = 0x800700B7u32 as i32;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(std::iter::once(0)).collect()
}

fn last_error(what: &str) -> Fail {
    Fail::new("box", format!("{what}: {}", std::io::Error::last_os_error()))
}

/// The container's SID, freed when dropped.
struct Sid(PSID);

impl Drop for Sid {
    fn drop(&mut self) {
        unsafe { FreeSid(self.0) };
    }
}

impl Sid {
    fn text(&self) -> String {
        let mut raw: *mut u16 = null_mut();
        if unsafe { ConvertSidToStringSidW(self.0, &mut raw) } == 0 {
            return String::new();
        }
        let mut len = 0;
        while unsafe { *raw.add(len) } != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, len) });
        unsafe { LocalFree(raw as _) };
        text
    }
}

/// Creates the profile, or finds the one already made under this name.
fn container_sid(name: &str) -> Res<Sid> {
    let wname = wide(name);
    let display = wide("hn sandbox");
    let mut sid: PSID = null_mut();
    let hr = unsafe { CreateAppContainerProfile(wname.as_ptr(), display.as_ptr(), display.as_ptr(), null(), 0, &mut sid) };
    if hr == ALREADY_EXISTS {
        let hr = unsafe { DeriveAppContainerSidFromAppContainerName(wname.as_ptr(), &mut sid) };
        if hr < 0 {
            return Err(Fail::new("box", format!("could not find the box profile {name} (0x{hr:08x})")));
        }
    } else if hr < 0 {
        return Err(Fail::new("box", format!("could not create the box profile {name} (0x{hr:08x})")));
    }
    Ok(Sid(sid))
}

/// Removes a session's profile. The SID is derived from the name, so a later box never reuses it by accident.
pub fn forget(name: &str) -> Res<()> {
    let hr = unsafe { DeleteAppContainerProfile(wide(name).as_ptr()) };
    if hr < 0 {
        return Err(Fail::new("box", format!("could not remove the box profile {name} (0x{hr:08x})")));
    }
    Ok(())
}

/// Adds an allow entry for the container to a folder's DACL, inherited by everything below it or by nothing.
fn grant(path: &str, sid: &Sid, mask: u32, inherit: bool) -> Res<()> {
    let wpath = wide(path);
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let rc = unsafe { GetNamedSecurityInfoW(wpath.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), &mut dacl, null_mut(), &mut descriptor) };
    if rc != 0 {
        return Err(Fail::new("box", format!("could not read the permissions of {path} (error {rc})")));
    }
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: if inherit { SUB_CONTAINERS_AND_OBJECTS_INHERIT } else { 0 },
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.0 as *mut u16,
        },
    };
    let mut updated: *mut ACL = null_mut();
    let rc = unsafe { SetEntriesInAclW(1, &access, dacl, &mut updated) };
    if rc != 0 {
        unsafe { LocalFree(descriptor as _) };
        return Err(Fail::new("box", format!("could not build permissions for {path} (error {rc})")));
    }
    // An inherited grant must reach what is already in the folder, so the change is propagated, which walks the
    // whole tree (the caller refuses drive roots). A single-folder grant is written to that folder alone, never walked.
    let rc = if inherit {
        unsafe { SetNamedSecurityInfoW(wpath.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), updated, null()) }
    } else {
        set_one(&wpath, updated)
    };
    unsafe {
        LocalFree(updated as _);
        LocalFree(descriptor as _);
    }
    if rc != 0 {
        return Err(Fail::new("box", format!("could not set the permissions of {path} (error {rc})")));
    }
    Ok(())
}

/// Writes a DACL to one folder with the old API, which does not touch anything below it.
fn set_one(path: &[u16], dacl: *mut ACL) -> u32 {
    let mut sd: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    let sdp = &mut sd as *mut SECURITY_DESCRIPTOR as PSECURITY_DESCRIPTOR;
    let ok = unsafe {
        InitializeSecurityDescriptor(sdp, SECURITY_DESCRIPTOR_REVISION) != 0
            && SetSecurityDescriptorDacl(sdp, 1, dacl, 0) != 0
            && SetSecurityDescriptorControl(sdp, SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERITED) != 0
            && SetFileSecurityW(path.as_ptr(), DACL_SECURITY_INFORMATION, sdp) != 0
    };
    if ok {
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(1) as u32
    }
}

/// An owned handle, closed when dropped.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn make_job(spec: &RunSpec) -> Res<Owned> {
    let job = Owned(unsafe { CreateJobObjectW(null(), null()) });
    if job.0.is_null() {
        return Err(last_error("could not create the job object"));
    }
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if let Some(count) = spec.processes {
        flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = count;
    }
    if let Some(bytes) = spec.memory {
        flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        limits.JobMemoryLimit = bytes as usize;
    }
    limits.BasicLimitInformation.LimitFlags = flags;
    let size = std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
    if unsafe { SetInformationJobObject(job.0, JobObjectExtendedLimitInformation, &limits as *const _ as _, size) } == 0 {
        return Err(last_error("could not set the job limits"));
    }
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_EXITWINDOWS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    };
    let size = std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32;
    if unsafe { SetInformationJobObject(job.0, JobObjectBasicUIRestrictions, &ui as *const _ as _, size) } == 0 {
        return Err(last_error("could not set the job's desktop limits"));
    }
    Ok(job)
}

/// What the started process's token and its job really are, read back from Windows rather than from what was asked.
fn report(process: HANDLE, job: HANDLE, sid: &Sid) -> String {
    let mut token: HANDLE = null_mut();
    let mut is_container: u32 = 0;
    let mut capabilities: i64 = -1;
    let mut integrity: i64 = -1;
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } != 0 {
        let token = Owned(token);
        let mut len = 0u32;
        unsafe { GetTokenInformation(token.0, TokenIsAppContainer, &mut is_container as *mut _ as _, 4, &mut len) };
        unsafe { GetTokenInformation(token.0, TokenCapabilities, null_mut(), 0, &mut len) };
        if len >= 4 {
            let mut buffer = vec![0u8; len as usize];
            if unsafe { GetTokenInformation(token.0, TokenCapabilities, buffer.as_mut_ptr() as _, len, &mut len) } != 0 {
                capabilities = i64::from(u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]));
            }
        }
        unsafe { GetTokenInformation(token.0, TokenIntegrityLevel, null_mut(), 0, &mut len) };
        if len > 0 {
            let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
            if unsafe { GetTokenInformation(token.0, TokenIntegrityLevel, buffer.as_mut_ptr() as _, len, &mut len) } != 0 {
                let label = unsafe { &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
                let count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) };
                if count > 0 {
                    integrity = i64::from(unsafe { *GetSidSubAuthority(label.Label.Sid, u32::from(count) - 1) });
                }
            }
        }
    }
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
    let queried = unsafe { QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &mut limits as *mut _ as _, size, null_mut()) } != 0;
    let flags = if queried { limits.BasicLimitInformation.LimitFlags } else { 0 };
    format!(
        "{{\"appContainer\":{},\"capabilities\":{},\"integrity\":{},\"sid\":{},\"job\":{{\"read\":{},\"killOnClose\":{},\"activeProcessLimit\":{},\"jobMemoryLimit\":{}}}}}",
        is_container != 0,
        capabilities,
        integrity,
        json_string(&sid.text()),
        queried,
        flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0,
        if flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS != 0 { i64::from(limits.BasicLimitInformation.ActiveProcessLimit) } else { -1 },
        if flags & JOB_OBJECT_LIMIT_JOB_MEMORY != 0 { limits.JobMemoryLimit as i64 } else { -1 },
    )
}

/// The standard handles that are real, made inheritable, without duplicates (the handle list refuses them).
fn std_handles() -> Vec<HANDLE> {
    let mut handles: Vec<HANDLE> = Vec::new();
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let handle = unsafe { GetStdHandle(which) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE || handles.contains(&handle) {
            continue;
        }
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } != 0 {
            handles.push(handle);
        }
    }
    handles
}

/// Starts the program in the box and waits for it. Returns its exit code. Every process it started dies with this helper.
pub fn run(spec: &RunSpec) -> Res<u32> {
    let sid = container_sid(&spec.name)?;
    for path in &spec.grants {
        grant(path, &sid, FILE_ALL_ACCESS, true)?;
    }
    for path in &spec.reads {
        grant(path, &sid, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, true)?;
    }
    for path in &spec.lists {
        grant(path, &sid, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE, false)?;
    }
    let job = make_job(spec)?;

    let capabilities = SECURITY_CAPABILITIES { AppContainerSid: sid.0, Capabilities: null_mut(), CapabilityCount: 0, Reserved: 0 };
    let handles = std_handles();
    let attribute_count = if handles.is_empty() { 1 } else { 2 };
    let mut size = 0usize;
    unsafe { InitializeProcThreadAttributeList(null_mut(), attribute_count, 0, &mut size) };
    let mut storage = vec![0u64; size.div_ceil(8)];
    let list = storage.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
    if unsafe { InitializeProcThreadAttributeList(list, attribute_count, 0, &mut size) } == 0 {
        return Err(last_error("could not prepare the process attributes"));
    }
    let result = (|| {
        let ok = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                &capabilities as *const _ as _,
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                null_mut(),
                null(),
            )
        };
        if ok == 0 {
            return Err(last_error("could not attach the box to the process"));
        }
        if !handles.is_empty() {
            let ok = unsafe {
                UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize, handles.as_ptr() as _, handles.len() * std::mem::size_of::<HANDLE>(), null_mut(), null())
            };
            if ok == 0 {
                return Err(last_error("could not limit the inherited handles"));
            }
        }
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = list;
        if !handles.is_empty() {
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
            startup.StartupInfo.hStdOutput = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
            startup.StartupInfo.hStdError = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        }
        let program = wide(&spec.program);
        let mut line = wide(&command_line(&spec.program, &spec.args));
        let environment = env_block(&spec.env);
        let cwd = wide(&spec.cwd);
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let created = unsafe {
            CreateProcessW(
                program.as_ptr(),
                line.as_mut_ptr(),
                null(),
                null(),
                i32::from(!handles.is_empty()),
                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                environment.as_ptr() as _,
                cwd.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        };
        if created == 0 {
            return Err(last_error(&format!("could not start {} in the box", spec.program)));
        }
        let process = Owned(info.hProcess);
        let thread = Owned(info.hThread);
        // In the job before it runs a single instruction, so nothing it starts can get out of the job first.
        if unsafe { AssignProcessToJobObject(job.0, process.0) } == 0 {
            let error = last_error("could not put the process in the job");
            unsafe { TerminateProcess(process.0, 1) };
            return Err(error);
        }
        if let Some(path) = &spec.report {
            if let Err(error) = std::fs::write(path, report(process.0, job.0, &sid)) {
                unsafe { TerminateProcess(process.0, 1) };
                return Err(Fail::new("io", format!("could not write the report: {error}")));
            }
        }
        unsafe { ResumeThread(thread.0) };
        unsafe { WaitForSingleObject(process.0, INFINITE) };
        let mut code = 1u32;
        unsafe { GetExitCodeProcess(process.0, &mut code) };
        Ok(code)
    })();
    unsafe { DeleteProcThreadAttributeList(list) };
    // The job handle closes when `job` drops, which kills anything the box left running.
    drop(job);
    result
}
