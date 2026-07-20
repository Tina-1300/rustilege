# rustilege

Rust library allowing you to recover current privileges under Windows

# Use 

```rust
use rustilege::{Rustilege, IntegrityLevel};

fn main() {
    let level = Rustilege::get_current_integrity_level();

    match level {
        IntegrityLevel::System => println!("Level: System"),
        IntegrityLevel::Administrator => println!("Level: Administrator"),
        IntegrityLevel::User => println!("Level: User"),
        IntegrityLevel::Low => println!("Level: Low"),
        IntegrityLevel::Guest => println!("Level: Guest"),
        IntegrityLevel::Error => eprintln!("Error: Unable to determine integrity level"),
    }
}
```