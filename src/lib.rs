/*
TODO : 

- Remove dependenci nix if is inutile on linux for code run
- unit test Linux and Windows 
- Refactoring code 
- Adding Documentation
- Adding CI/CD
- vérifier si ses possible de suprimmer le repository et repartire de 0 quand on a un repo tout propre sans perdre la library 
sur la package rust 


*/

#[cfg(target_os = "windows")]
pub struct Rustilege;

pub enum IntegrityLevel {
    System = 0x00004000,
    Administrator = 0x00003000,
    User = 0x00002000,
    Low = 0x00001000,
    Guest = 0x00000000,
    Error = 0xFFFFFFFF, 
}

#[cfg(target_os = "windows")]
impl Rustilege{

    pub fn get_current_integrity_level() -> IntegrityLevel{

        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, TokenIntegrityLevel, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, SID, PSID,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token_handle: HANDLE = HANDLE::default();
        let current_process = unsafe { GetCurrentProcess() };

        if unsafe { OpenProcessToken(current_process, TOKEN_QUERY, &mut token_handle) }.is_err() {
            return IntegrityLevel::Error;
        }

        let mut token_info_size = 0;
        let _ = unsafe {
            GetTokenInformation(
                token_handle,
                TokenIntegrityLevel,
                None,
                0,
                &mut token_info_size,
            )
        };

        if token_info_size == 0 {
            let _ = unsafe { CloseHandle(token_handle) };
            return IntegrityLevel::Error;
        }

        let mut buffer = vec![0u8; token_info_size as usize];
        let token_info_ptr = buffer.as_mut_ptr() as *mut std::ffi::c_void;

        if unsafe {
            GetTokenInformation(
                token_handle,
                TokenIntegrityLevel,
                Some(token_info_ptr),
                token_info_size,
                &mut token_info_size,
            )
        }.is_err(){
            let _ = unsafe { CloseHandle(token_handle) };
            return IntegrityLevel::Error;
        }

        let token_label = unsafe { &*(token_info_ptr as *const TOKEN_MANDATORY_LABEL) };
        let sid_ptr: PSID = token_label.Label.Sid;

        if sid_ptr.0.is_null() {
            let _ = unsafe { CloseHandle(token_handle) };
            return IntegrityLevel::Error;
        }

        let sid = sid_ptr.0 as *const SID;
        let sub_auth_count = unsafe { (*sid).SubAuthorityCount as usize };

        if sub_auth_count == 0 || sub_auth_count > 15 {
            let _ = unsafe { CloseHandle(token_handle) };
            return IntegrityLevel::Error;
        }

        let integrity_level = unsafe { (*sid).SubAuthority[sub_auth_count - 1] };
        let _ = unsafe { CloseHandle(token_handle) };

        match integrity_level {
            0x00000000 => IntegrityLevel::Guest, 
            0x00001000 => IntegrityLevel::Low,
            0x00002000 => IntegrityLevel::User,
            0x00003000 => IntegrityLevel::Administrator, 
            0x00004000 => IntegrityLevel::System,
            _ => IntegrityLevel::Error,
        }

    }
  

}


#[cfg(target_os = "linux")]
pub struct Rustilege;


#[cfg(target_os = "linux")]
impl Rustilege {
    pub fn get_current_integrity_level() -> IntegrityLevel {

        use std::{fs::Metadata, os::unix::fs::MetadataExt};
        let uid: Option<u32> = std::fs::metadata("/proc/self").map(|m:Metadata|m.uid()).ok();

        if uid == Some(0) {
            IntegrityLevel::Administrator
        } else if uid >= Some(1000) {
            IntegrityLevel::User
        }else{
            IntegrityLevel::Guest
        }

        /*
        // code it's not works : 
        use nix::unistd::Uid;
        let uid = Uid::effective();
        if uid.as_raw() == 0 {
            IntegrityLevel::Administrator
        } else if uid.as_raw() >= 1000 {
            IntegrityLevel::User
        } else {
            IntegrityLevel::Guest
        }
        */

    }
}



// if the code is not under Linux or Windows
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub struct Rustilege;

// if the code is not under Linux or Windows
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
impl Rustilege {
    pub fn get_current_integrity_level() -> IntegrityLevel {
        IntegrityLevel::Error // OS not supported
    }
}
