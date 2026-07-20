//! # Rustilege
//!
//! A Windows privilege utility library.
//!
//! ## Platform support
//!
//! Currently supported:
//!
//! - Windows

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, HANDLE};

#[cfg(target_os = "windows")]
pub struct Rustilege;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IntegrityLevel {
    Guest = 0x00000000,
    Low = 0x00001000,
    User = 0x00002000,
    Administrator = 0x00003000,
    System = 0x00004000,
}


/// Errors returned when retrieving Windows security information.
#[derive(Debug)]
pub enum RustilegeError {

    /// Unable to open the current process token.
    OpenProcessToken(windows::core::Error),

    /// Unable to query token information.
    GetTokenInformation(windows::core::Error),

    /// Invalid Windows security identifier.
    InvalidSid,

    /// Unknown integrity level returned by Windows.
    UnknownIntegrityLevel(u32),
}


#[cfg(target_os = "windows")]
struct TokenHandle(HANDLE);


#[cfg(target_os = "windows")]
impl Drop for TokenHandle {

    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}


#[cfg(target_os = "windows")]
impl Rustilege {

    pub fn get_current_integrity_level()
        -> Result<IntegrityLevel, RustilegeError>
    {

        use windows::Win32::Security::{
            GetTokenInformation,
            TokenIntegrityLevel,
            TOKEN_MANDATORY_LABEL,
            TOKEN_QUERY,
            SID,
            PSID,
        };

        use windows::Win32::System::Threading::{
            GetCurrentProcess,
            OpenProcessToken,
        };


        let mut raw_handle = HANDLE::default();


        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY,
                &mut raw_handle
            )
        }
        .map_err(RustilegeError::OpenProcessToken)?;


        let _token = TokenHandle(raw_handle);


        let mut token_info_size = 0u32;


        unsafe {
            let _ = GetTokenInformation(
                raw_handle,
                TokenIntegrityLevel,
                None,
                0,
                &mut token_info_size,
            );
        }


        if token_info_size == 0 {
            return Err(
                RustilegeError::GetTokenInformation(
                    windows::core::Error::from_thread()
                )
            );
        }


        let mut buffer = vec![0u8; token_info_size as usize];


        unsafe {
            GetTokenInformation(
                raw_handle,
                TokenIntegrityLevel,
                Some(buffer.as_mut_ptr() as *mut _),
                token_info_size,
                &mut token_info_size,
            )
        }
        .map_err(RustilegeError::GetTokenInformation)?;


        let token_label =
            unsafe {
                &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL)
            };


        let sid: PSID = token_label.Label.Sid;


        if sid.0.is_null() {
            return Err(RustilegeError::InvalidSid);
        }


        let sid = sid.0 as *const SID;


        let sub_authority_count =
            unsafe {
                (*sid).SubAuthorityCount as usize
            };


        if sub_authority_count == 0 || sub_authority_count > 15 {
            return Err(RustilegeError::InvalidSid);
        }


        let integrity_level =
            unsafe {
                (*sid)
                    .SubAuthority[sub_authority_count - 1]
            };


        match integrity_level {

            0x00000000 =>
                Ok(IntegrityLevel::Guest),

            0x00001000 =>
                Ok(IntegrityLevel::Low),

            0x00002000 =>
                Ok(IntegrityLevel::User),

            0x00003000 =>
                Ok(IntegrityLevel::Administrator),

            0x00004000 =>
                Ok(IntegrityLevel::System),

            value =>
                Err(
                    RustilegeError::UnknownIntegrityLevel(value)
                ),
        }
    }
}



#[cfg(test)]
mod tests {

    use super::{
        Rustilege,
        IntegrityLevel,
    };


    #[test]
    fn test_get_current_integrity_level() {

        let level =
            Rustilege::get_current_integrity_level()
                .expect("failed retrieving integrity level");


        assert!(
            matches!(
                level,
                IntegrityLevel::System
                | IntegrityLevel::Administrator
                | IntegrityLevel::User
                | IntegrityLevel::Low
                | IntegrityLevel::Guest
            )
        );
    }


    #[test]
    fn test_integrity_level_values() {

        assert_eq!(
            IntegrityLevel::System as u32,
            0x00004000
        );

        assert_eq!(
            IntegrityLevel::Administrator as u32,
            0x00003000
        );
    }
}
