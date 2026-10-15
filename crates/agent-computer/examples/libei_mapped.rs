//! Manual end-to-end check of coordinate mapping through the real backend:
//! take a screenshot (records the scale), then move to a point given in
//! SCREENSHOT coordinates. Moves only — no click.
//!
//! Usage: cargo run -p agent-computer --example libei_mapped -- <img_x> <img_y>

use agent_computer::detect_backend;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (x, y): (i32, i32) = (args[1].parse()?, args[2].parse()?);
    let backend = detect_backend();
    println!("backend={}", backend.id());
    let dest = std::env::temp_dir()
        .join("agent-libei-check")
        .join("shot.png");
    let meta = backend.screenshot(&dest).await?;
    println!("display={:?} image={:?}", meta.display, meta.image);
    let c = meta.capture();
    let phys = c.map_to_display([x, y]);
    println!("image ({x},{y}) -> physical ({},{})", phys[0], phys[1]);
    backend.move_to([x, y]).await?;
    println!("moved");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    Ok(())
}
