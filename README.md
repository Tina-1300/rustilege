# rustilege

Rust library allowing you to recover current privileges under Windows

# Use 

```rust
use rustilege::{
    Rustilege,
    IntegrityLevel,
};


fn main() {

    match Rustilege::get_current_integrity_level() {

        Ok(level) => {

            match level {

                IntegrityLevel::System => {
                    println!("Process running as SYSTEM");
                }


                IntegrityLevel::Administrator => {
                    println!("Administrator privileges");
                }


                IntegrityLevel::User => {
                    println!("Standard user");
                }


                IntegrityLevel::Low => {
                    println!("Low integrity process");
                }


                IntegrityLevel::Guest => {
                    println!("Guest process");
                }
            }
        }


        Err(error) => {
            eprintln!(
                "Failed getting integrity level: {:?}",
                error
            );
        }
    }
}

```