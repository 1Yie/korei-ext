//! Minimal stand-in for the `core-graphics` crate so `macos.rs` can be
//! typechecked on non-Apple targets (`cargo check -p agent-computer
//! --features check-macos`). Only compiled under that feature; the real
//! crate is used on actual macOS builds.
//!
//! **Keep signatures in sync with core-graphics 0.25** — this exists to
//! catch API drift in `macos.rs`, not to emulate behaviour. Constructors
//! return `Err` so anything accidentally *called* off-target fails loudly
//! instead of pretending to inject input.

#![allow(dead_code)]

pub mod geometry {
    /// Mirrors `core_graphics::geometry::CGPoint`.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq)]
    pub struct CGPoint {
        pub x: f64,
        pub y: f64,
    }

    impl CGPoint {
        pub fn new(x: f64, y: f64) -> Self {
            Self { x, y }
        }
    }
}

pub mod event {
    use super::event_source::CGEventSource;
    use super::geometry::CGPoint;

    pub type CGKeyCode = u16;
    pub type CGScrollEventUnit = u32;

    #[derive(Clone, Copy, Debug)]
    pub enum CGEventType {
        MouseMoved,
        LeftMouseDown,
        LeftMouseUp,
        RightMouseDown,
        RightMouseUp,
        LeftMouseDragged,
        RightMouseDragged,
        OtherMouseDown,
        OtherMouseUp,
        OtherMouseDragged,
        ScrollWheel,
        KeyDown,
        KeyUp,
        FlagsChanged,
    }

    #[derive(Clone, Copy, Debug)]
    pub enum CGMouseButton {
        Left,
        Right,
        Center,
    }

    #[derive(Clone, Copy, Debug)]
    pub enum CGEventTapLocation {
        HID,
        Session,
        AnnotatedSession,
    }

    /// Mirrors `core_graphics::event::ScrollEventUnit`.
    pub struct ScrollEventUnit {}

    impl ScrollEventUnit {
        pub const PIXEL: CGScrollEventUnit = 0;
        pub const LINE: CGScrollEventUnit = 1;
    }

    /// Opaque stand-in — constructors fail so synthetic input never
    /// "succeeds" off-target.
    pub struct CGEvent {
        _private: (),
    }

    impl CGEvent {
        pub fn new_mouse_event(
            _source: CGEventSource,
            _mouse_type: CGEventType,
            _mouse_cursor_position: CGPoint,
            _mouse_button: CGMouseButton,
        ) -> Result<CGEvent, ()> {
            Err(())
        }

        pub fn new_keyboard_event(
            _source: CGEventSource,
            _keycode: CGKeyCode,
            _keydown: bool,
        ) -> Result<CGEvent, ()> {
            Err(())
        }

        pub fn new_scroll_event(
            _source: CGEventSource,
            _units: CGScrollEventUnit,
            _wheel_count: u32,
            _wheel1: i32,
            _wheel2: i32,
            _wheel3: i32,
        ) -> Result<CGEvent, ()> {
            Err(())
        }

        pub fn post(&self, _tap_location: CGEventTapLocation) {}

        pub fn set_string_from_utf16_unchecked(&self, _buf: &[u16]) {}

        pub fn set_string(&self, string: &str) {
            let buf: Vec<u16> = string.encode_utf16().collect();
            self.set_string_from_utf16_unchecked(&buf);
        }
    }
}

pub mod event_source {
    /// Mirrors `core_graphics::event_source::CGEventSourceStateID`.
    #[derive(Clone, Copy, Debug)]
    pub enum CGEventSourceStateID {
        HIDSystemState,
        CombinedSessionState,
        Private,
    }

    /// Mirrors `core_graphics::event_source::CGEventSource`.
    pub struct CGEventSource {
        _private: (),
    }

    impl CGEventSource {
        pub fn new(_state_id: CGEventSourceStateID) -> Result<CGEventSource, ()> {
            Err(())
        }
    }
}

pub mod sys {
    /// Opaque raw-event type used only behind a pointer in the
    /// `CGEventGetLocation` extern declaration.
    pub enum CGEvent {}
}
