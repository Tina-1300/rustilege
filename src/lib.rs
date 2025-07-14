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
