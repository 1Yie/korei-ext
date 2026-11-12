use rquickjs::allocator::{Allocator, RustAllocator};
use std::{alloc::Layout, cell::Cell, mem, ptr, rc::Rc};

// RustAllocator 0.14 rounds payloads to u64 alignment and prefixes a usize header.
const ALIGN: usize = mem::align_of::<u64>();
const HEADER: usize = if mem::size_of::<usize>() > ALIGN {
    mem::size_of::<usize>()
} else {
    ALIGN
};

#[derive(Clone)]
pub(crate) struct MemoryStatus(Rc<MemoryState>);

struct MemoryState {
    used: Cell<usize>,
    failed: Cell<bool>,
}

impl MemoryStatus {
    pub(crate) fn failed(&self) -> bool {
        self.0.failed.get()
    }
}

pub(crate) struct BoundedAllocator {
    inner: RustAllocator,
    limit: usize,
    status: MemoryStatus,
}

impl BoundedAllocator {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            inner: RustAllocator,
            limit,
            status: MemoryStatus(Rc::new(MemoryState {
                used: Cell::new(0),
                failed: Cell::new(false),
            })),
        }
    }

    pub(crate) fn status(&self) -> MemoryStatus {
        self.status.clone()
    }

    fn charge(size: usize) -> Option<usize> {
        let rounded = (size.checked_add(ALIGN - 1)? / ALIGN).checked_mul(ALIGN)?;
        let charge = rounded.checked_add(HEADER)?;
        Layout::from_size_align(charge, ALIGN).ok()?;
        Some(charge)
    }

    fn reject(&self) -> *mut u8 {
        self.status.0.failed.set(true);
        ptr::null_mut()
    }

    fn replacement_usage(&self, size: usize, previous: usize) -> Option<usize> {
        let used = self
            .status
            .0
            .used
            .get()
            .checked_sub(previous)?
            .checked_add(Self::charge(size)?)?;
        (!self.status.failed() && used <= self.limit).then_some(used)
    }

    fn committed(&self, pointer: *mut u8, used: usize) -> *mut u8 {
        if pointer.is_null() {
            self.reject()
        } else {
            self.status.0.used.set(used);
            pointer
        }
    }
}

// SAFETY: Every non-null pointer is delegated unchanged to the same RustAllocator.
// Accounting includes its rounded payload and header; failed replacements keep
// the original allocation and charge. Only live pointers reach size/free/realloc.
unsafe impl Allocator for BoundedAllocator {
    fn alloc(&mut self, size: usize) -> *mut u8 {
        let Some(used) = self.replacement_usage(size, 0) else {
            return self.reject();
        };
        let pointer = self.inner.alloc(size);
        self.committed(pointer, used)
    }

    fn calloc(&mut self, count: usize, size: usize) -> *mut u8 {
        if count == 0 || size == 0 {
            return ptr::null_mut();
        }
        let Some(size_total) = count.checked_mul(size) else {
            return self.reject();
        };
        let Some(used) = self.replacement_usage(size_total, 0) else {
            return self.reject();
        };
        let pointer = self.inner.calloc(count, size);
        self.committed(pointer, used)
    }

    unsafe fn dealloc(&mut self, pointer: *mut u8) {
        if !pointer.is_null() {
            // SAFETY: The caller supplies a live pointer allocated by this instance.
            let charge = unsafe { RustAllocator::usable_size(pointer) } + HEADER;
            unsafe { self.inner.dealloc(pointer) };
            self.status.0.used.set(self.status.0.used.get() - charge);
        }
    }

    unsafe fn realloc(&mut self, pointer: *mut u8, new_size: usize) -> *mut u8 {
        if pointer.is_null() {
            return self.alloc(new_size);
        }
        // SAFETY: Reading size and reallocating use the same live delegated pointer.
        let previous = unsafe { RustAllocator::usable_size(pointer) } + HEADER;
        let Some(used) = self.replacement_usage(new_size, previous) else {
            return self.reject();
        };
        let pointer = unsafe { self.inner.realloc(pointer, new_size) };
        self.committed(pointer, used)
    }

    unsafe fn usable_size(pointer: *mut u8) -> usize {
        if pointer.is_null() {
            0
        } else {
            // SAFETY: All allocated pointers and their headers belong to RustAllocator.
            unsafe { RustAllocator::usable_size(pointer) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignment_header_and_zero_size_accounting_match_delegate() {
        let mut allocator = BoundedAllocator::new(1024);
        assert!(allocator.calloc(0, usize::MAX).is_null());
        assert!(allocator.calloc(usize::MAX, 0).is_null());
        assert!(!allocator.status.failed());
        let empty = allocator.alloc(0);
        assert!(!empty.is_null());
        assert_eq!(allocator.status.0.used.get(), HEADER);
        let pointer = allocator.calloc(3, 3);
        assert!(!pointer.is_null());
        assert_eq!(pointer as usize % ALIGN, 0);
        // SAFETY: calloc initialized at least nine bytes; both allocations are live.
        unsafe {
            assert_eq!(BoundedAllocator::usable_size(empty), 0);
            assert_eq!(
                BoundedAllocator::usable_size(pointer),
                9usize.div_ceil(ALIGN) * ALIGN
            );
            assert!(std::slice::from_raw_parts(pointer, 9)
                .iter()
                .all(|&byte| byte == 0));
            allocator.dealloc(pointer);
            allocator.dealloc(empty);
            allocator.dealloc(ptr::null_mut());
        }
        assert_eq!(allocator.status.0.used.get(), 0);
    }

    #[test]
    fn realloc_preserves_data_and_charge_on_rejection() {
        let mut allocator = BoundedAllocator::new(HEADER + 3 * ALIGN);
        let pointer = allocator.alloc(ALIGN);
        assert!(!pointer.is_null());
        // SAFETY: Each replacement is checked before using it; rejection leaves
        // the original pointer live and all reads stay within initialized bytes.
        unsafe {
            pointer.write_bytes(0x5a, ALIGN);
            let grown = allocator.realloc(pointer, 3 * ALIGN);
            assert!(!grown.is_null());
            assert_eq!(allocator.status.0.used.get(), HEADER + 3 * ALIGN);
            assert_eq!(std::slice::from_raw_parts(grown, ALIGN), vec![0x5a; ALIGN]);
            let shrunk = allocator.realloc(grown, 1);
            assert!(!shrunk.is_null());
            assert_eq!(allocator.status.0.used.get(), HEADER + ALIGN);
            assert!(allocator.realloc(shrunk, usize::MAX).is_null());
            assert_eq!(*shrunk, 0x5a);
            assert_eq!(allocator.status.0.used.get(), HEADER + ALIGN);
            assert!(allocator.status.failed());
            allocator.dealloc(shrunk);
        }
        assert_eq!(allocator.status.0.used.get(), 0);
    }

    #[test]
    fn overflow_limit_and_failure_state_are_isolated() {
        for calloc in [false, true] {
            let mut allocator = BoundedAllocator::new(usize::MAX);
            let pointer = if calloc {
                allocator.calloc(usize::MAX, 2)
            } else {
                allocator.alloc(usize::MAX)
            };
            assert!(pointer.is_null());
            assert!(allocator.status.failed());
            assert_eq!(allocator.status.0.used.get(), 0);
        }
        for size in [usize::MAX - (ALIGN - 1), isize::MAX as usize + 1] {
            let mut allocator = BoundedAllocator::new(usize::MAX);
            assert!(allocator.alloc(size).is_null());
            assert!(allocator.status.failed());
            assert_eq!(allocator.status.0.used.get(), 0);
        }
        let mut allocator = BoundedAllocator::new(HEADER + ALIGN);
        let pointer = allocator.alloc(1);
        assert!(!pointer.is_null());
        assert!(allocator.alloc(0).is_null());
        assert!(allocator.status.failed());
        // SAFETY: The rejected second allocation leaves the first one live.
        unsafe { allocator.dealloc(pointer) };
        assert_eq!(allocator.status.0.used.get(), 0);
        let mut other = BoundedAllocator::new(HEADER);
        // SAFETY: Null realloc is handled as alloc; zero payload still owns a header.
        let empty = unsafe { other.realloc(ptr::null_mut(), 0) };
        assert!(!empty.is_null());
        let resized = unsafe { other.realloc(empty, 0) };
        assert!(!resized.is_null());
        unsafe { other.dealloc(resized) };
        assert_eq!(other.status.0.used.get(), 0);
        assert!(!other.status.failed());
    }

    #[test]
    fn runtime_teardown_releases_every_delegated_allocation() {
        let allocator = BoundedAllocator::new(8 * 1024 * 1024);
        let status = allocator.status();
        let runtime = rquickjs::Runtime::new_with_alloc(allocator).unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| ctx.eval::<(), _>("const v={}; v.self=v").unwrap());
        assert!(status.0.used.get() > 0);
        drop(context);
        drop(runtime);
        assert_eq!(status.0.used.get(), 0);
        assert!(!status.failed());
    }
}
