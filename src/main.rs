fn main() {
    // This crate is a library. The binary exists only so `cargo test` and `cargo run`
    // have a target; print the fleet canary so `cargo run` shows something meaningful.
    println!("audit-log — SuperInstance fleet");
    println!("canary 0x24a555471370b18d  (see tests/canary.rs)");
}
