//! Manual check of the keyboard path: press and release Shift (no visible
//! effect on its own). Verifies libei key emission end to end.

use agent_computer::detect_backend;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let backend = detect_backend();
    println!("backend={}", backend.id());
    backend.key("shift", Some(50)).await?;
    println!("pressed+released shift");
    Ok(())
}
