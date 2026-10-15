//! Wayland desktop backend — libei through the RemoteDesktop portal.
//!
//! Wayland has no way for an ordinary client to move the pointer: `xdotool`
//! injects through XWayland, which KWin only applies to X clients, so clicks
//! land nowhere on native windows. The sanctioned route is the compositor's
//! input-emulation socket: the `RemoteDesktop` portal grants a session, hands
//! back an EIS socket (`ConnectToEIS`), and we speak libei on it.
//!
//! **Grant is remembered.** The session is created with
//! `PersistMode::ExplicitlyRevoked`, so the compositor asks the user once and
//! then stays quiet on later runs.
//!
//! **One connection per process.** `DesktopBackend` instances are created per
//! session, but the portal grant and EIS socket are a single resource, so the
//! connection lives in a process-wide `OnceLock` and every backend shares it.
//! It is established lazily — the first input call — so sessions that only
//! take screenshots never touch the portal.
//!
//! **Coordinates.** Screenshot space → display pixels (`Capture::map_to_display`)
//! → logical pixels. KWin reports the pointer region in logical pixels with a
//! physical `scale` (1.25 here: a 2560×1440 screen is a 2048×1152 region), and
//! `motion_absolute` takes logical pixels. Dividing by `scale` is the whole
//! mapping; passing physical pixels straight through is what put clicks off
//! target under `xdotool`.
//!
//! **Keyboard.** EI keys are evdev keycodes (physical positions), not
//! characters. Only US-layout ASCII is mapped here; other text is refused with
//! a message rather than typed wrong.

use std::os::unix::net::UnixStream;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use futures_util::StreamExt;
use reis::ei;
use reis::event::{DeviceCapability, EiEvent};

use crate::traits::{Capture, MouseButton, ScrollDir};

/// evdev button codes (`linux/input-event-codes.h`).
const BTN_LEFT: u32 = 0x110;
const BTN_RIGHT: u32 = 0x111;
const BTN_MIDDLE: u32 = 0x112;

/// Wheel detents: EI's `scroll_discrete` counts 120 units per notch.
const WHEEL_NOTCH: i32 = 120;

/// Bounded wait for the portal and the first device list — a dead portal must
/// not hang a tool call forever.
const SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// One live EIS connection. Holds the protocol objects we send through; the
/// high-level `reis::event` wrappers only describe devices, they cannot emit.
struct Connection {
    context: ei::Context,
    /// Pointer device: the `ei_device` plus its absolute-motion, button and
    /// wheel interfaces, all bound to the same emulation sequence.
    pointer: Emitter,
    /// Keyboard device, when the compositor grants one.
    keyboard: Option<Emitter>,
    /// Logical size of the pointer region, and its physical `scale`.
    region_logical: [f32; 2],
    scale: f32,
    /// One frame at a time: `start_emulating` … `stop_emulating` must not
    /// interleave between concurrent tool calls.
    gate: tokio::sync::Mutex<u32>,
}

/// A device's protocol objects plus the `serial` the compositor last resumed
/// it with (required by every emulation request).
struct Emitter {
    device: ei::Device,
    absolute: Option<ei::PointerAbsolute>,
    button: Option<ei::Button>,
    scroll: Option<ei::Scroll>,
    keyboard: Option<ei::Keyboard>,
    serial: u32,
}

/// Process-wide connection. `Err` is cached too, so a refused grant is reported
/// on every call instead of re-prompting the portal each time.
static CONNECTION: OnceLock<std::result::Result<Arc<Connection>, String>> = OnceLock::new();

/// The EIS connection for this process, establishing it on first use.
async fn connection() -> Result<Arc<Connection>> {
    if let Some(c) = CONNECTION.get() {
        return c.clone().map_err(|e| anyhow!(e));
    }
    let made = tokio::time::timeout(SETUP_TIMEOUT, establish())
        .await
        .map_err(|_| anyhow!("timed out waiting for the desktop portal to grant input"))
        .and_then(|r| r);
    let stored = made.map_err(|e| format!("{e:#}"));
    // Two tasks racing here both establish; the first to store wins and the
    // other's socket is dropped. Acceptable: this is a once-per-process cost.
    let _ = CONNECTION.set(stored);
    CONNECTION
        .get()
        .expect("just set")
        .clone()
        .map_err(|e| anyhow!(e))
}

/// Portal handshake → EIS socket → libei handshake → pointer and keyboard.
///
/// The libei event stream is `!Send` (reis keeps `Box<dyn FnOnce>` callbacks
/// in it), so it cannot be held across an `.await` inside a `#[async_trait]`
/// future. The whole negotiation therefore runs on its own thread with its own
/// single-threaded runtime, and only `Send` results cross back.
async fn establish() -> Result<Arc<Connection>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("agent-libei".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Err(anyhow::Error::from(e)));
                    return;
                }
            };
            // `negotiate` owns the `!Send` event stream and keeps draining it
            // on this thread after handing back the `Send` connection.
            rt.block_on(negotiate(tx));
        })
        .context("start the input thread")?;
    rx.await
        .map_err(|_| anyhow!("the input thread exited before it finished"))?
}

/// Everything that touches the `!Send` event stream. Returns owned, `Send`
/// protocol objects.
async fn negotiate(done: tokio::sync::oneshot::Sender<Result<Arc<Connection>>>) {
    match negotiate_inner().await {
        Ok((conn, mut events)) => {
            let _ = done.send(Ok(conn));
            // Drain the stream on this thread for the life of the process. The
            // compositor sends pings and frame acks; reis answers them while we
            // read. Left unread, the socket backs up and input stalls.
            while let Some(event) = events.next().await {
                if event.is_err() {
                    break;
                }
            }
        }
        Err(e) => {
            let _ = done.send(Err(e));
        }
    }
}

/// The negotiation proper. Returns the `Send` connection plus the live event
/// stream, which must stay on the thread that created it.
async fn negotiate_inner() -> Result<(Arc<Connection>, reis::tokio::EiConvertEventStream)> {
    use ashpd::desktop::remote_desktop::{
        ConnectToEISOptions, DeviceType, RemoteDesktop, SelectDevicesOptions,
    };
    use ashpd::desktop::{CreateSessionOptions, PersistMode};

    let rd = RemoteDesktop::new()
        .await
        .context("connect to the RemoteDesktop portal")?;
    let session = rd
        .create_session(CreateSessionOptions::default())
        .await
        .context("create a RemoteDesktop session")?;
    rd.select_devices(
        &session,
        SelectDevicesOptions::default()
            .set_devices(DeviceType::Pointer | DeviceType::Keyboard)
            .set_persist_mode(PersistMode::ExplicitlyRevoked),
    )
    .await
    .context("request pointer and keyboard")?;
    rd.start(&session, None, Default::default())
        .await
        .context("start the RemoteDesktop session")?
        .response()
        .context("input access was refused")?;
    let fd = rd
        .connect_to_eis(&session, ConnectToEISOptions::default())
        .await
        .context("open the input socket")?;

    // The grant lasts as long as the portal session. Park both for the life of
    // the process so dropping them never revokes input mid-run.
    std::mem::forget(session);
    std::mem::forget(rd);

    let context = ei::Context::new(UnixStream::from(fd)).context("wrap the input socket")?;
    let (_connection, mut events) = context
        .handshake_tokio("agent", ei::handshake::ContextType::Sender)
        .await
        .context("libei handshake")?;

    // Pointer and keyboard are announced as separate devices. A device is only
    // usable once the compositor has resumed it (`DeviceResumed`), which also
    // carries the serial every emulation request needs.
    let mut pointer: Option<(reis::event::Device, [f32; 2], f32)> = None;
    let mut keyboard_dev: Option<reis::event::Device> = None;
    let mut pointer_resumed: Option<u32> = None;
    let mut keyboard_resumed: Option<u32> = None;
    while let Some(event) = events.next().await {
        match event.context("libei event")? {
            EiEvent::SeatAdded(evt) => {
                evt.seat.bind_capabilities(
                    DeviceCapability::Pointer
                        | DeviceCapability::PointerAbsolute
                        | DeviceCapability::Keyboard
                        | DeviceCapability::Button
                        | DeviceCapability::Scroll,
                );
                let _ = context.flush();
            }
            EiEvent::DeviceAdded(evt) => {
                // Classify by the interfaces a device implements, not by
                // regions: KDE announces a keyboard with no region, but also
                // announces button/scroll-only devices with none. Absolute
                // pointer + a region is the one we aim with.
                let d = &evt.device;
                if pointer.is_none() && d.interface::<ei::PointerAbsolute>().is_some() {
                    if let Some(r) = d.regions().first() {
                        pointer = Some((
                            d.clone(),
                            [r.width as f32, r.height as f32],
                            r.scale.max(0.01),
                        ));
                    }
                } else if keyboard_dev.is_none() && d.interface::<ei::Keyboard>().is_some() {
                    keyboard_dev = Some(d.clone());
                }
            }
            EiEvent::DeviceResumed(evt) => {
                if pointer.as_ref().is_some_and(|(d, _, _)| d == &evt.device) {
                    pointer_resumed = Some(evt.serial);
                } else if keyboard_dev.as_ref().is_some_and(|d| d == &evt.device) {
                    keyboard_resumed = Some(evt.serial);
                }
            }
            _ => {}
        }
        // Stop once the pointer and a keyboard are both resumed. Do NOT stop on
        // "pointer resumed, no keyboard seen yet": KDE announces the keyboard
        // after the pointer, and leaving early drops it.
        if pointer_resumed.is_some() && keyboard_resumed.is_some() {
            break;
        }
    }

    let (pdev, region_logical, scale) = pointer
        .ok_or_else(|| anyhow!("the compositor granted input but exposed no pointer region"))?;
    let pointer = Emitter::from_device(&pdev, pointer_resumed.unwrap_or(0));
    let keyboard = keyboard_dev.map(|d| Emitter::from_device(&d, keyboard_resumed.unwrap_or(0)));

    Ok((
        Arc::new(Connection {
            context,
            pointer,
            keyboard,
            region_logical,
            scale,
            gate: tokio::sync::Mutex::new(0),
        }),
        events,
    ))
}

impl Emitter {
    /// Pull the protocol objects off a high-level device. The interfaces are
    /// optional — a device may not implement, say, scroll.
    fn from_device(d: &reis::event::Device, serial: u32) -> Self {
        Self {
            device: d.device().clone(),
            absolute: d.interface::<ei::PointerAbsolute>(),
            button: d.interface::<ei::Button>(),
            scroll: d.interface::<ei::Scroll>(),
            keyboard: d.interface::<ei::Keyboard>(),
            serial,
        }
    }
}

/// The pointer's logical-pixel target for a screenshot-space coordinate.
///
/// `display` is the physical capture size (what `Capture` maps into); dividing
/// the physical position by the region's `scale` lands it in logical pixels,
/// which is what `motion_absolute` takes.
pub fn logical_target(
    cap: Option<Capture>,
    at: [i32; 2],
    region: [f32; 2],
    scale: f32,
) -> [f32; 2] {
    let phys = match cap {
        Some(c) => c.map_to_display(at),
        None => at,
    };
    let logical = [phys[0] as f32 / scale, phys[1] as f32 / scale];
    [
        logical[0].clamp(0.0, (region[0] - 1.0).max(0.0)),
        logical[1].clamp(0.0, (region[1] - 1.0).max(0.0)),
    ]
}

/// evdev code for a mouse button.
pub fn button_code(b: MouseButton) -> u32 {
    match b {
        MouseButton::Left => BTN_LEFT,
        MouseButton::Right => BTN_RIGHT,
        MouseButton::Middle => BTN_MIDDLE,
    }
}

/// Wheel delta in EI discrete units for one step in `dir`.
pub fn scroll_delta(dir: ScrollDir, steps: i32) -> (i32, i32) {
    let n = steps * WHEEL_NOTCH;
    match dir {
        ScrollDir::Up => (0, -n),
        ScrollDir::Down => (0, n),
        ScrollDir::Left => (-n, 0),
        ScrollDir::Right => (n, 0),
    }
}

/// Send one frame of input: `start_emulating` → the events → `frame` →
/// `stop_emulating`, all tagged with the device's resume serial. Without the
/// bracketing the compositor drops the events without an error.
async fn emit<F>(conn: &Connection, dev: &Emitter, f: F) -> Result<()>
where
    F: FnOnce(&Emitter),
{
    let mut seq = conn.gate.lock().await;
    *seq = seq.wrapping_add(1);
    let sequence = *seq;
    dev.device.start_emulating(dev.serial, sequence);
    f(dev);
    dev.device.frame(dev.serial, now_micros());
    dev.device.stop_emulating(dev.serial);
    conn.context
        .flush()
        .context("send input to the compositor")?;
    Ok(())
}

/// Event timestamp in microseconds, as EI expects. The compositor only uses it
/// for ordering, so a monotonic clock is enough.
fn now_micros() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_target_divides_physical_by_scale() {
        // 2560×1440 physical screen at scale 1.25 → 2048×1152 logical region.
        let cap = Capture {
            display: [2560, 1440],
            image: [1429, 804],
        };
        // Image centre → physical centre (1280, 720) → logical (1024, 576).
        let t = logical_target(Some(cap), [715, 402], [2048.0, 1152.0], 1.25);
        assert!((t[0] - 1024.0).abs() < 1.5, "{t:?}");
        assert!((t[1] - 576.0).abs() < 1.5, "{t:?}");
    }

    #[test]
    fn logical_target_clamps_into_the_region() {
        let t = logical_target(None, [99_999, -4], [2048.0, 1152.0], 1.25);
        assert_eq!(t, [2047.0, 0.0]);
    }

    #[test]
    fn unscaled_region_is_identity() {
        let t = logical_target(None, [100, 200], [1920.0, 1080.0], 1.0);
        assert_eq!(t, [100.0, 200.0]);
    }

    #[test]
    fn buttons_use_evdev_codes() {
        assert_eq!(button_code(MouseButton::Left), 0x110);
        assert_eq!(button_code(MouseButton::Right), 0x111);
        assert_eq!(button_code(MouseButton::Middle), 0x112);
    }

    #[test]
    fn scroll_steps_are_wheel_notches() {
        assert_eq!(scroll_delta(ScrollDir::Down, 3), (0, 360));
        assert_eq!(scroll_delta(ScrollDir::Left, 1), (-120, 0));
    }
}

use std::path::Path;

use crate::traits::{DesktopBackend, ScreenshotMeta};
use crate::x11::{self, CaptureTool};

/// Wayland desktop backend: screenshots through the same external tools as
/// X11, input through the portal-granted libei connection.
///
/// Holds its own capture scale (`last`) because input coordinates are mapped
/// through the most recent screenshot, exactly as on X11.
pub struct LibeiBackend {
    capture_tool: CaptureTool,
    last: std::sync::Mutex<Option<Capture>>,
}

impl LibeiBackend {
    /// Build the backend. The portal grant is NOT requested here — that waits
    /// for the first input call, so a screenshot-only session never prompts.
    pub fn new(capture_tool: CaptureTool) -> Self {
        Self {
            capture_tool,
            last: std::sync::Mutex::new(None),
        }
    }

    /// Screenshot-space point → logical pixels of the pointer region. Uses the
    /// last capture's scale; with no capture yet, the point is taken as-is.
    async fn logical(&self, at: [i32; 2]) -> Result<(Arc<Connection>, [f32; 2])> {
        let conn = connection().await?;
        let cap = *self.last.lock().unwrap_or_else(|e| e.into_inner());
        let t = logical_target(cap, at, conn.region_logical, conn.scale);
        Ok((conn, t))
    }
}

#[async_trait::async_trait]
impl DesktopBackend for LibeiBackend {
    fn id(&self) -> &'static str {
        "wayland"
    }

    async fn screenshot(&self, dest: &Path) -> Result<ScreenshotMeta> {
        x11::capture(self.capture_tool, &self.last, dest).await
    }

    async fn click(&self, button: MouseButton, at: [i32; 2]) -> Result<()> {
        let (conn, t) = self.logical(at).await?;
        let code = button_code(button);
        emit(&conn, &conn.pointer, |d| {
            if let Some(a) = &d.absolute {
                a.motion_absolute(t[0], t[1]);
            }
        })
        .await?;
        emit(&conn, &conn.pointer, |d| {
            if let Some(b) = &d.button {
                b.button(code, reis::ei::button::ButtonState::Press);
            }
        })
        .await?;
        emit(&conn, &conn.pointer, |d| {
            if let Some(b) = &d.button {
                b.button(code, reis::ei::button::ButtonState::Released);
            }
        })
        .await
    }

    async fn double_click(&self, at: [i32; 2]) -> Result<()> {
        self.click(MouseButton::Left, at).await?;
        self.click(MouseButton::Left, at).await
    }

    async fn move_to(&self, at: [i32; 2]) -> Result<()> {
        let (conn, t) = self.logical(at).await?;
        emit(&conn, &conn.pointer, |d| {
            if let Some(a) = &d.absolute {
                a.motion_absolute(t[0], t[1]);
            }
        })
        .await
    }

    async fn drag(&self, from: [i32; 2], to: [i32; 2]) -> Result<()> {
        self.move_to(from).await?;
        let (conn, t) = self.logical(from).await?;
        emit(&conn, &conn.pointer, |d| {
            if let Some(b) = &d.button {
                b.button(BTN_LEFT, reis::ei::button::ButtonState::Press);
            }
        })
        .await?;
        let (conn, t2) = self.logical(to).await?;
        emit(&conn, &conn.pointer, |d| {
            if let Some(a) = &d.absolute {
                a.motion_absolute(t2[0], t2[1]);
            }
        })
        .await?;
        let _ = t;
        emit(&conn, &conn.pointer, |d| {
            if let Some(b) = &d.button {
                b.button(BTN_LEFT, reis::ei::button::ButtonState::Released);
            }
        })
        .await
    }

    async fn type_text(&self, text: &str) -> Result<()> {
        // Keys are evdev positions, so only the US layout is mapped here.
        // Anything else is refused: typing the wrong character is worse than
        // typing nothing.
        let conn = connection().await?;
        let kb = conn
            .keyboard
            .as_ref()
            .ok_or_else(|| anyhow!("the compositor granted no keyboard"))?;
        for ch in text.chars() {
            let (code, shift) = us_keycode(ch).ok_or_else(|| {
                anyhow!("cannot type {ch:?} — only US-layout ASCII is supported over libei")
            })?;
            if shift {
                emit(&conn, kb, |d| {
                    if let Some(k) = &d.keyboard {
                        k.key(KEY_LEFTSHIFT, reis::ei::keyboard::KeyState::Press);
                    }
                })
                .await?;
            }
            emit(&conn, kb, |d| {
                if let Some(k) = &d.keyboard {
                    k.key(code, reis::ei::keyboard::KeyState::Press);
                }
            })
            .await?;
            emit(&conn, kb, |d| {
                if let Some(k) = &d.keyboard {
                    k.key(code, reis::ei::keyboard::KeyState::Released);
                }
            })
            .await?;
            if shift {
                emit(&conn, kb, |d| {
                    if let Some(k) = &d.keyboard {
                        k.key(KEY_LEFTSHIFT, reis::ei::keyboard::KeyState::Released);
                    }
                })
                .await?;
            }
        }
        Ok(())
    }

    async fn key(&self, combo: &str, hold_ms: Option<u64>) -> Result<()> {
        let conn = connection().await?;
        let kb = conn
            .keyboard
            .as_ref()
            .ok_or_else(|| anyhow!("the compositor granted no keyboard"))?;
        let parts: Vec<u32> = combo
            .split('+')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|name| key_name_code(name).ok_or_else(|| anyhow!("unknown key {name:?}")))
            .collect::<Result<_>>()?;
        if parts.is_empty() {
            bail!("empty key combo");
        }
        let hold = Duration::from_millis(hold_ms.unwrap_or(0).min(30_000));
        // Keys are released in reverse even if a press fails — a stuck Ctrl or
        // Shift on the user's desktop is worse than a short tool error.
        let mut pressed: Vec<u32> = Vec::new();
        let mut result: Result<()> = Ok(());
        for &code in &parts {
            let r = emit(&conn, kb, |d| {
                if let Some(k) = &d.keyboard {
                    k.key(code, reis::ei::keyboard::KeyState::Press);
                }
            })
            .await;
            pressed.push(code);
            if r.is_err() {
                result = r;
                break;
            }
        }
        if result.is_ok() && hold_ms.is_some() {
            tokio::time::sleep(hold).await;
        }
        for &code in pressed.iter().rev() {
            let _ = emit(&conn, kb, |d| {
                if let Some(k) = &d.keyboard {
                    k.key(code, reis::ei::keyboard::KeyState::Released);
                }
            })
            .await;
        }
        result
    }

    async fn scroll(&self, dir: ScrollDir, amount: i32, at: Option<[i32; 2]>) -> Result<()> {
        if let Some(at) = at {
            self.move_to(at).await?;
        }
        let conn = connection().await?;
        let (dx, dy) = scroll_delta(dir, amount.clamp(1, 500));
        emit(&conn, &conn.pointer, |d| {
            if let Some(s) = &d.scroll {
                s.scroll_discrete(dx, dy);
            }
        })
        .await
    }

    async fn cursor_position(&self) -> Result<[i32; 2]> {
        // EI is a send-only protocol: the compositor never reports where the
        // pointer is. Refuse rather than return a guess the model would act on.
        bail!("reading the pointer position is not available under Wayland (libei is send-only)")
    }

    async fn launch_app(&self, command: &str) -> Result<()> {
        crate::launch::spawn_detached(&crate::traits::parse_launch(command)?).await
    }

    async fn prepare(&self) -> Result<()> {
        connection().await.map(|_| ())
    }
}

/// evdev code for left Shift.
const KEY_LEFTSHIFT: u32 = 42;

/// Map a single key name (`ctrl`, `Return`, `a`, `F5`, …) to its evdev code.
/// Covers the names the `computer` tool documents; anything else is refused.
fn key_name_code(name: &str) -> Option<u32> {
    let lower = name.to_ascii_lowercase();
    let code = match lower.as_str() {
        "ctrl" | "control" | "lctrl" => 29,
        "shift" | "lshift" => 42,
        "alt" | "lalt" => 56,
        "super" | "meta" | "win" | "lmeta" => 125,
        "tab" => 15,
        "return" | "enter" => 28,
        "escape" | "esc" => 1,
        "space" => 57,
        "backspace" => 14,
        "delete" | "del" => 111,
        "up" => 103,
        "down" => 108,
        "left" => 105,
        "right" => 106,
        "home" => 102,
        "end" => 107,
        "pageup" => 104,
        "pagedown" => 109,
        f if f.len() >= 2 && f.starts_with('f') => match f[1..].parse::<u32>() {
            Ok(n @ 1..=10) => 58 + n, // F1..F10 = 59..68
            Ok(11) => 87,             // F11
            Ok(12) => 88,             // F12
            _ => return None,
        },
        single if single.chars().count() == 1 => {
            return us_keycode(single.chars().next()?).map(|(c, _)| c);
        }
        _ => return None,
    };
    Some(code)
}

/// US-layout evdev code and whether Shift is needed, for one ASCII character.
fn us_keycode(ch: char) -> Option<(u32, bool)> {
    let lower = ch.to_ascii_lowercase();
    let shift = ch.is_ascii_uppercase()
        || matches!(
            ch,
            '!' | '@'
                | '#'
                | '$'
                | '%'
                | '^'
                | '&'
                | '*'
                | '('
                | ')'
                | '_'
                | '+'
                | '{'
                | '}'
                | '|'
                | ':'
                | '"'
                | '<'
                | '>'
                | '?'
                | '~'
        );
    let code = match lower {
        'a' => 30,
        'b' => 48,
        'c' => 46,
        'd' => 32,
        'e' => 18,
        'f' => 33,
        'g' => 34,
        'h' => 35,
        'i' => 23,
        'j' => 36,
        'k' => 37,
        'l' => 38,
        'm' => 50,
        'n' => 49,
        'o' => 24,
        'p' => 25,
        'q' => 16,
        'r' => 19,
        's' => 31,
        't' => 20,
        'u' => 22,
        'v' => 47,
        'w' => 17,
        'x' => 45,
        'y' => 21,
        'z' => 44,
        '1' | '!' => 2,
        '2' | '@' => 3,
        '3' | '#' => 4,
        '4' | '$' => 5,
        '5' | '%' => 6,
        '6' | '^' => 7,
        '7' | '&' => 8,
        '8' | '*' => 9,
        '9' | '(' => 10,
        '0' | ')' => 11,
        '-' | '_' => 12,
        '=' | '+' => 13,
        '[' | '{' => 26,
        ']' | '}' => 27,
        ';' | ':' => 39,
        '\'' | '"' => 40,
        '`' | '~' => 41,
        '\\' | '|' => 43,
        ',' | '<' => 51,
        '.' | '>' => 52,
        '/' | '?' => 53,
        ' ' => 57,
        '\n' | '\r' => 28,
        '\t' => 15,
        _ => return None,
    };
    Some((code, shift))
}

#[cfg(test)]
mod send_bounds {
    fn assert_send_sync<T: Send + Sync>() {}

    /// Every `DesktopBackend` method is an `async_trait` future, which must be
    /// `Send`. That only holds if the connection it awaits on is `Send + Sync`
    /// — the `!Send` event stream lives on its own thread for this reason.
    #[test]
    fn connection_is_send_sync() {
        assert_send_sync::<super::Connection>();
        assert_send_sync::<super::Emitter>();
    }
}
