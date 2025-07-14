#[cfg(test)]
mod tests {
    use super::{Rustilege, IntegrityLevel};

    #[test]
    fn test_get_current_integrity_level(){
        let level = Rustilege::get_current_integrity_level();

        match level {
            IntegrityLevel::System
            | IntegrityLevel::Administrator
            | IntegrityLevel::User
            | IntegrityLevel::Low
            | IntegrityLevel::Guest => {
                assert!(true);
            }
            IntegrityLevel::Error => {
                panic!("Error retrieving integrity level");
            }
        }
    }
}