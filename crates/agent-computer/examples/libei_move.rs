//! Manual check: move the pointer to a point through the real backend chosen
//! by `detect_backend()`. Moves only — no click.
//!
//! Usage: cargo run -p agent-computer --example libei_move -- <x> <y>
//! (x, y) are logical pixels of the pointer region, e.g. 1024 576.

use agent_computer::{detect_backend, Capture};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (x, y): (i32, i32) = (args[1].parse()?, args[2].parse()?);
    let backend = detect_backend();
    println!("backend={}", backend.id());
    // No screenshot taken, so coordinates are used as-is (identity mapping).
    // `Capture` is re-exported only to show the mapping type is in scope.
    let _unused: Option<Capture> = None;
    backend.move_to([x, y]).await?;
    println!("moved to ({x}, {y})");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    Ok(())
}
