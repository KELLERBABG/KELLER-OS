//! Kernel heap: an address-ordered free-list allocator.
//!
//! `SPECIFICATION.md` §3.1 asks for a lock-free-ish linked-list allocator with static
//! containment and no unbounded allocation in the critical path. This keeps that shape
//! but fixes three real defects of the previous version:
//!
//! * `dealloc` never merged neighbouring blocks, so any long-running workload (the
//!   compositor backbuffer, per-session vault shards, mesh reassembly buffers)
//!   fragmented the heap until allocation failed. Blocks are now inserted in address
//!   order and coalesced with both neighbours.
//! * `align` from the caller was ignored; every allocation was forced to 32 bytes, which
//!   is wrong for the 4096-aligned structures the graphics path will need. Alignment is
//!   now honoured up to any power of two, with the request's own waste bounded by the
//!   alignment.
//! * the heap range was hardcoded at `0x1000000`. It is now derived from the boot
//!   memory map (`bootinfo`), which matters as soon as the backbuffer is allocated.
//!
//! Block layout: `[FreeBlock header][optional alignment gap][8-byte back-pointer][data]`.
//! The back-pointer lets `dealloc` recover the block base without a side table.

use crate::panic;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicPtr, Ordering};

const MIN_ALIGN: usize = 16;
const HEADER_SIZE: usize = core::mem::size_of::<FreeBlock>();

struct FreeBlock {
    size: usize,
    next: *mut FreeBlock,
}

pub struct SovereignAllocator {
    head: AtomicPtr<FreeBlock>,
    lock: AtomicBool,
}

impl SovereignAllocator {
    pub const fn new() -> Self {
        Self {
            head: AtomicPtr::new(ptr::null_mut()),
            lock: AtomicBool::new(false),
        }
    }

    fn acquire(&self) {
        while self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    fn release(&self) {
        self.lock.store(false, Ordering::Release);
    }

    /// Seeds the heap with one free block spanning `[start, start + size)`.
    pub unsafe fn init(&self, start: usize, size: usize) {
        let block = start as *mut FreeBlock;
        ptr::write(
            block,
            FreeBlock {
                size,
                next: ptr::null_mut(),
            },
        );
        self.head.store(block, Ordering::SeqCst);
    }

    /// Inserts a freed block, keeping the list sorted by address and merging with the
    /// previous and/or next block whenever they are physically adjacent.
    unsafe fn insert_free(&self, block: *mut FreeBlock) {
        let address = block as usize;
        let mut previous: *mut FreeBlock = ptr::null_mut();
        let mut current = self.head.load(Ordering::SeqCst);

        while !current.is_null() && (current as usize) < address {
            previous = current;
            current = (*current).next;
        }

        (*block).next = current;

        // Merge with the following block when contiguous.
        if !current.is_null() && address + (*block).size == current as usize {
            (*block).size += (*current).size;
            (*block).next = (*current).next;
        }

        if previous.is_null() {
            self.head.store(block, Ordering::SeqCst);
        } else {
            (*previous).next = block;
            // Merge with the preceding block when contiguous.
            let previous_end = previous as usize + (*previous).size;
            if previous_end == block as usize {
                (*previous).size += (*block).size;
                (*previous).next = (*block).next;
            }
        }
    }
}

fn align_up(value: usize, align: usize) -> usize {
    (value + (align - 1)) & !(align - 1)
}

fn request_size(layout: &Layout) -> usize {
    align_up(layout.size().max(1), MIN_ALIGN)
}

unsafe impl GlobalAlloc for SovereignAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(MIN_ALIGN);
        let wanted = request_size(&layout);

        self.acquire();

        let mut previous: *mut FreeBlock = ptr::null_mut();
        let mut current = self.head.load(Ordering::SeqCst);

        while !current.is_null() {
            let block_start = current as usize;
            // Leave HEADER_SIZE at the front so the header of a successor block and the
            // back-pointer always have room inside this block.
            let payload = align_up(block_start + HEADER_SIZE, align);
            let consumed = (payload - block_start) + wanted;

            if consumed <= (*current).size {
                let leftover = (*current).size - consumed;

                if leftover >= HEADER_SIZE + MIN_ALIGN {
                    // Split: the remainder becomes a free block in the same list slot.
                    let remainder = (payload + wanted) as *mut FreeBlock;
                    ptr::write(
                        remainder,
                        FreeBlock {
                            size: leftover,
                            next: (*current).next,
                        },
                    );
                    if previous.is_null() {
                        self.head.store(remainder, Ordering::SeqCst);
                    } else {
                        (*previous).next = remainder;
                    }
                } else if previous.is_null() {
                    self.head.store((*current).next, Ordering::SeqCst);
                } else {
                    (*previous).next = (*current).next;
                }

                // Back-pointer so dealloc can find the block base.
                ptr::write((payload - 8) as *mut usize, block_start);
                self.release();
                return payload as *mut u8;
            }

            previous = current;
            current = (*current).next;
        }

        self.release();
        ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let payload = ptr as usize;
        let block_start = ptr::read((payload - 8) as *const usize);
        let total = (payload - block_start) + request_size(&layout);

        self.acquire();
        let block = block_start as *mut FreeBlock;
        ptr::write(
            block,
            FreeBlock {
                size: total,
                next: ptr::null_mut(),
            },
        );
        self.insert_free(block);
        self.release();
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = self.alloc(layout);
        if !ptr.is_null() {
            for i in 0..layout.size() {
                ptr::write_volatile(ptr.add(i), 0);
            }
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
        let new_ptr = self.alloc(new_layout);
        if !new_ptr.is_null() {
            ptr::copy_nonoverlapping(ptr, new_ptr, core::cmp::min(layout.size(), new_size));
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}

#[global_allocator]
pub static ALLOCATOR: SovereignAllocator = SovereignAllocator::new();

pub static HEAP_START: AtomicU64 = AtomicU64::new(0);
pub static HEAP_SIZE: AtomicU64 = AtomicU64::new(0);

pub fn heap_span() -> Option<(u64, u64)> {
    let start = HEAP_START.load(Ordering::Relaxed);
    let size = HEAP_SIZE.load(Ordering::Relaxed);
    if start == 0 || size == 0 {
        None
    } else {
        Some((start, size))
    }
}

/// Initialises the heap and registers it as a panic-scrub region.
///
/// # Safety
/// Must be called exactly once, with a range that is mapped and unused by the kernel
/// image, and before any allocation happens.
pub unsafe fn init_heap(start: u64, size: u64) {
    HEAP_START.store(start, Ordering::Relaxed);
    HEAP_SIZE.store(size, Ordering::Relaxed);
    ALLOCATOR.init(start as usize, size as usize);
    panic::register_scrub_region(start, size);
}
