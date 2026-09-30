//! Four-level paging: the address spaces the isolation claim actually rests on.
//!
//! The boot tables (`src/boot.rs`) identity-map the low 4 GiB with 2 MiB pages and hand the
//! kernel one PML4 in `cr3`. That single table is enough for a kernel that only ever runs its
//! own code — and it is exactly what makes per-process isolation impossible: with one address
//! space, every task sees every other task's memory, whatever the privilege level says.
//!
//! This module builds a PML4 **per process** and switches `cr3` on every task switch, so
//! `SpaceA ∩ SpaceB = ∅` holds in hardware rather than by convention:
//!
//! * every process PML4 copies the kernel's identity map into its `PDPT[0..4]`
//!   supervisor-only, so kernel code, heap and framebuffer stay reachable while a process
//!   runs — and stay unreachable *from* the process, because the U/S bit is 0 all the way
//!   down that branch;
//! * the process's own pages live at 256 GiB ([`USER_BASE`]), a region the boot identity map
//!   leaves empty, and are the only pages with U/S = 1 along the whole walk;
//! * two processes that use the *same* virtual addresses therefore reach different physical
//!   frames, which is the property the harness can check by walking both tables and comparing.
//!
//! Frames come from the kernel heap. The heap sits inside the identity map, so a frame's
//! address is at once the pointer the kernel writes through and the physical address the CPU
//! wants in a page-table entry or in `cr3` — no second allocator, no mapping of the mapping,
//! and no translation table to keep in sync. That is also why a "frame" here is just a `u64`.

use crate::arch::cpu;
use crate::panic;
use crate::println;
use alloc::alloc::{alloc, dealloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

pub const PAGE_SIZE: u64 = 4096;
pub const ENTRY_COUNT: usize = 512;

/// Entry flag bits (SDM vol. 3, 4-level paging).
pub const PRESENT: u64 = 1 << 0;
pub const WRITABLE: u64 = 1 << 1;
pub const USER: u64 = 1 << 2;
pub const HUGE: u64 = 1 << 7;
pub const ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// What the kernel's own pages get: present, writable, and never reachable from ring 3.
pub const SUPERVISOR_RW: u64 = PRESENT | WRITABLE;
/// User pages: `USER_RX` deliberately has no write bit, so a process cannot rewrite its own
/// code, and `USER_RW` is what stacks and data pages get.
pub const USER_RX: u64 = PRESENT | USER;
pub const USER_RW: u64 = PRESENT | WRITABLE | USER;

/// User-space virtual base: 256 GiB. Two properties matter. It is far above the boot identity
/// map (the low 4 GiB, `bootinfo::IDENTITY_MAP_LIMIT`), so no user page can ever shadow a
/// kernel page; and it is inside PML4[0], so every process can share the kernel's own tables
/// instead of duplicating the whole map.
pub const USER_BASE: u64 = 0x40_0000_0000;

/// How many of the boot PDPT's entries the kernel identity map occupies (4 x 1 GiB).
const KERNEL_PDPT_ENTRIES: usize = 4;

/// Per-space bookkeeping limits. A process here gets code, data, stack and a peer window;
/// 16 leaves and 16 tables leave headroom without an unbounded list.
const MAX_OWNED_TABLES: usize = 16;
const MAX_LEAF_PAGES: usize = 16;

static FRAMES_IN_USE: AtomicU64 = AtomicU64::new(0);
static FRAMES_TOTAL: AtomicU64 = AtomicU64::new(0);

/// The `cr3` the kernel itself runs on (the boot tables).
static mut KERNEL_CR3: u64 = 0;
/// First entries of the boot PDPT, copied into every process space verbatim.
static mut KERNEL_IDENTITY: [u64; KERNEL_PDPT_ENTRIES] = [0; KERNEL_PDPT_ENTRIES];
static mut READY: bool = false;

pub fn frames_in_use() -> u64 {
    FRAMES_IN_USE.load(Ordering::Relaxed)
}

pub fn frames_total() -> u64 {
    FRAMES_TOTAL.load(Ordering::Relaxed)
}

pub fn kernel_cr3() -> u64 {
    unsafe { *core::ptr::addr_of!(KERNEL_CR3) }
}

pub fn ready() -> bool {
    unsafe { *core::ptr::addr_of!(READY) }
}

fn frame_layout() -> Layout {
    // 4 KiB *and* 4 KiB-aligned: the allocator honours any power-of-two alignment, so the
    // payload address is the page frame address.
    Layout::from_size_align(PAGE_SIZE as usize, PAGE_SIZE as usize).unwrap()
}

/// Allocates one 4 KiB frame, zeroed.
///
/// Page tables must be zeroed before use: an unwritten entry from whatever the heap block
/// held before would present as a mapped page.
pub fn alloc_frame() -> u64 {
    let pointer = unsafe { alloc(frame_layout()) };
    if pointer.is_null() {
        println!("[!!] PAGING: heap exhausted, no room for a 4 KiB frame");
        unsafe { panic::lockdown("paging frame allocation failure") };
    }
    unsafe { ptr::write_bytes(pointer, 0, PAGE_SIZE as usize) };
    FRAMES_IN_USE.fetch_add(1, Ordering::Relaxed);
    FRAMES_TOTAL.fetch_add(1, Ordering::Relaxed);
    pointer as u64
}

/// Returns a frame to the heap. Callers must have removed every reference to it first.
pub unsafe fn free_frame(address: u64) {
    if address == 0 {
        return;
    }
    FRAMES_IN_USE.fetch_sub(1, Ordering::Relaxed);
    dealloc(address as *mut u8, frame_layout());
}

fn entry_at(table: u64, index: usize) -> u64 {
    debug_assert!(index < ENTRY_COUNT);
    unsafe { ptr::read_volatile((table as *const u64).add(index)) }
}

fn set_entry(table: u64, index: usize, value: u64) {
    debug_assert!(index < ENTRY_COUNT);
    unsafe { ptr::write_volatile((table as *mut u64).add(index), value) };
}

fn index_of(virtual_address: u64, shift: u32) -> usize {
    ((virtual_address >> shift) & 0x1FF) as usize
}

/// One translated page.
#[derive(Clone, Copy)]
pub struct Walk {
    /// Physical frame the virtual address resolves to.
    pub phys: u64,
    /// Flags of the leaf entry (the page itself).
    pub leaf: u64,
    /// True when U/S is set on *every* level, i.e. CPL 3 may touch this page.
    pub user_reachable: bool,
}

impl Walk {
    pub fn is_user(&self) -> bool {
        self.user_reachable
    }
}

/// Walks `pml4` for `virt` and returns the translation, or `None` when any level is absent.
///
/// A walk is safe on any `cr3` because every table frame is inside the kernel's identity map:
/// the kernel can inspect another address space without switching to it, which is exactly what
/// makes the isolation checks possible from the outside.
pub fn walk(pml4: u64, virt: u64) -> Option<Walk> {
    if pml4 == 0 {
        return None;
    }
    let mut user_reachable = true;
    let mut table = pml4;
    // PML4, PDPT, PD and PT. A level with PS set terminates the walk early: the kernel's
    // identity map uses 2 MiB pages, so a walk that insisted on four levels would report the
    // kernel as unmapped - the very mapping every process space has to carry.
    for (level, shift) in [(0usize, 39u32), (1, 30), (2, 21), (3, 12)] {
        let entry = entry_at(table, index_of(virt, shift));
        if entry & PRESENT == 0 {
            return None;
        }
        user_reachable &= entry & USER != 0;
        if entry & HUGE != 0 {
            let page_size = 1u64 << shift;
            return Some(Walk {
                phys: (entry & ADDRESS_MASK & !(page_size - 1)) | (virt & (page_size - 1)),
                leaf: entry & !ADDRESS_MASK,
                user_reachable,
            });
        }
        if level == 3 {
            return Some(Walk {
                phys: (entry & ADDRESS_MASK) | (virt & (PAGE_SIZE - 1)),
                leaf: entry & !ADDRESS_MASK,
                user_reachable,
            });
        }
        table = entry & ADDRESS_MASK;
    }
    None
}

/// Reads `init` from the live boot tables, so no symbol from `src/boot.rs` has to be exported
/// and the module keeps working if that bootstrap is ever rewritten.
///
/// # Safety
/// Must run once, after paging is on (it is) and before any address space is created.
pub unsafe fn init() {
    let cr3 = cpu::read_cr3();
    let pml4_entry = entry_at(cr3, 0);
    if pml4_entry & PRESENT == 0 {
        println!("[!!] PAGING: boot PML4[0] is not present - cannot discover the identity map");
        panic::lockdown("paging bootstrap failure");
    }
    let kernel_pdpt = pml4_entry & ADDRESS_MASK;
    *core::ptr::addr_of_mut!(KERNEL_CR3) = cr3;
    for index in 0..KERNEL_PDPT_ENTRIES {
        let entry = entry_at(kernel_pdpt, index);
        if entry & PRESENT == 0 {
            println!(
                "[!!] PAGING: identity map stops at {:#x} - a {} MiB frame is not mapped",
                (index as u64) * 0x4000_0000,
                index + 1
            );
            panic::lockdown("paging bootstrap failure");
        }
        *core::ptr::addr_of_mut!(KERNEL_IDENTITY[index]) = entry;
    }
    *core::ptr::addr_of_mut!(READY) = true;
    println!(
        "[OK] PAGING: boot tables at cr3={:#x}, identity map {:.0} GiB (2 MiB pages, supervisor), user base {:#x}",
        cr3,
        (KERNEL_PDPT_ENTRIES as u64) * 1,
        USER_BASE
    );
}

/// Switches the CPU back to the kernel's own address space.
pub fn activate_kernel() {
    unsafe { cpu::write_cr3(kernel_cr3()) };
}

/// One process's address space: its `cr3`, the tables it owns, and the frames it maps.
pub struct AddressSpace {
    name: &'static str,
    /// Physical address of the PML4, i.e. the value `cr3` takes while this space is active.
    pub cr3: u64,
    /// The process's own PDPT under PML4[0]; the kernel identity entries are copies.
    root: u64,
    owned: [u64; MAX_OWNED_TABLES],
    owned_count: usize,
    leaves: [u64; MAX_LEAF_PAGES],
    leaf_count: usize,
}

impl AddressSpace {
    /// Builds an empty space: a fresh PML4 plus the kernel's identity map, supervisor-only.
    pub fn new(name: &'static str) -> Self {
        let mut space = Self {
            name,
            cr3: 0,
            root: 0,
            owned: [0; MAX_OWNED_TABLES],
            owned_count: 0,
            leaves: [0; MAX_LEAF_PAGES],
            leaf_count: 0,
        };
        let cr3 = alloc_frame();
        let root = alloc_frame();
        for index in 0..KERNEL_PDPT_ENTRIES {
            let entry = unsafe { *core::ptr::addr_of!(KERNEL_IDENTITY[index]) };
            set_entry(root, index, entry);
        }
        // U/S = 1 here only opens a path *through* this level: the copied supervisor entries
        // below keep their own U/S = 0, and the CPU ANDs the bits along the walk, so the
        // kernel stays unreachable from ring 3.
        set_entry(cr3, 0, root | PRESENT | WRITABLE | USER);
        space.cr3 = cr3;
        space.root = root;
        space.push_table(root);
        space
    }

    fn push_table(&mut self, table: u64) {
        if self.owned_count < MAX_OWNED_TABLES {
            self.owned[self.owned_count] = table;
            self.owned_count += 1;
        }
    }

    fn table_or_alloc(&mut self, parent: u64, index: usize) -> u64 {
        let entry = entry_at(parent, index);
        if entry & PRESENT != 0 {
            return entry & ADDRESS_MASK;
        }
        let table = alloc_frame();
        set_entry(parent, index, table | PRESENT | WRITABLE | USER);
        self.push_table(table);
        table
    }

    /// Maps one 4 KiB page. Only the user region is managed here; the kernel branch of the
    /// space is never editable from this API, which is what keeps a process from remapping the
    /// kernel out from under itself.
    pub fn map_page(&mut self, virt: u64, phys: u64, flags: u64) -> bool {
        if virt < USER_BASE || virt % PAGE_SIZE != 0 || phys % PAGE_SIZE != 0 {
            return false;
        }
        if self.leaf_count >= MAX_LEAF_PAGES || self.owned_count >= MAX_OWNED_TABLES {
            return false;
        }
        let pml4_entry = entry_at(self.cr3, index_of(virt, 39));
        if pml4_entry & PRESENT == 0 {
            return false;
        }
        let pdpt = pml4_entry & ADDRESS_MASK;
        let pd = self.table_or_alloc(pdpt, index_of(virt, 30));
        let pt = self.table_or_alloc(pd, index_of(virt, 21));
        set_entry(pt, index_of(virt, 12), phys | flags);
        // Remember the leaf frame so teardown can hand it back to the heap.
        let already = (0..self.leaf_count).any(|index| self.leaves[index] == phys);
        if !already {
            self.leaves[self.leaf_count] = phys;
            self.leaf_count += 1;
        }
        true
    }

    /// Removes a leaf mapping and invalidates the TLB entry for it.
    pub fn unmap_page(&mut self, virt: u64) -> bool {
        if virt < USER_BASE {
            return false;
        }
        let pml4_entry = entry_at(self.cr3, index_of(virt, 39));
        let pdpt_entry = entry_at(pml4_entry & ADDRESS_MASK, index_of(virt, 30));
        if pdpt_entry & PRESENT == 0 {
            return false;
        }
        let pd_entry = entry_at(pdpt_entry & ADDRESS_MASK, index_of(virt, 21));
        if pd_entry & PRESENT == 0 {
            return false;
        }
        let pt = pd_entry & ADDRESS_MASK;
        let index = index_of(virt, 12);
        let entry = entry_at(pt, index);
        if entry & PRESENT == 0 {
            return false;
        }
        set_entry(pt, index, 0);
        cpu::invalidate_page(virt);
        true
    }

    /// Translation as seen from this space (independent of which `cr3` is live).
    pub fn translate(&self, virt: u64) -> Option<Walk> {
        walk(self.cr3, virt)
    }

    /// Makes this space the live one. Every write to `cr3` flushes non-global TLB entries, so
    /// the previous space's user mappings cannot outlive the switch.
    pub fn activate(&self) {
        unsafe { cpu::write_cr3(self.cr3) };
    }

    /// Copies `length` bytes from a user virtual address into kernel memory.
    ///
    /// This is the only way the kernel may read a user pointer: the walk has to run on *this*
    /// space, and the page has to be one a user task could reach (U/S = 1 along every level).
    /// A kernel address handed to a syscall therefore fails here instead of being dereferenced
    /// as if the caller were trusted — the bug that turns a syscall boundary into a privilege
    /// escalation.
    pub fn copy_from_user(&self, virt: u64, destination: &mut [u8]) -> Option<usize> {
        let length = destination.len();
        let mut copied = 0usize;
        while copied < length {
            let address = virt.checked_add(copied as u64)?;
            let translation = self.translate(address)?;
            if !translation.is_user() || !translation.user_reachable {
                return None;
            }
            let frame_offset = (translation.phys & (PAGE_SIZE - 1)) as usize;
            let page_room = (PAGE_SIZE as usize) - frame_offset;
            let chunk = core::cmp::min(page_room, length - copied);
            unsafe {
                ptr::copy_nonoverlapping(
                    translation.phys as *const u8,
                    destination.as_mut_ptr().add(copied),
                    chunk,
                );
            }
            copied += chunk;
        }
        Some(copied)
    }

    /// Writes bytes into one of this space's own mapped pages through the identity map.
    ///
    /// Used to place a program image into its code page before the task ever runs: the page is
    /// reachable from the kernel as a physical frame, and from the process as its `USER_BASE`
    /// address, but the two views are the same memory.
    pub fn write_user(&mut self, virt: u64, bytes: &[u8]) -> bool {
        let mut written = 0usize;
        while written < bytes.len() {
            let address = virt + written as u64;
            let translation = match self.translate(address) {
                Some(walk) if walk.user_reachable => walk,
                _ => return false,
            };
            let frame_offset = (translation.phys & (PAGE_SIZE - 1)) as usize;
            let page_room = (PAGE_SIZE as usize) - frame_offset;
            let chunk = core::cmp::min(page_room, bytes.len() - written);
            unsafe {
                ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(written),
                    translation.phys as *mut u8,
                    chunk,
                );
            }
            written += chunk;
        }
        true
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns every frame this space owns to the heap.
    ///
    /// Refusing to tear down the live space is deliberate: freeing the page table the CPU is
    /// walking would turn the next instruction fetch into a triple fault, and the caller is
    /// expected to hand the kernel's own `cr3` back first.
    pub fn teardown(self) {
        if cpu::read_cr3() == self.cr3 {
            println!(
                "[!!] PAGING: refusing to free the live address space of '{}'",
                self.name
            );
            unsafe { panic::lockdown("paging teardown of an active address space") };
        }
        unsafe {
            for index in 0..self.leaf_count {
                free_frame(self.leaves[index]);
            }
            for index in 0..self.owned_count {
                free_frame(self.owned[index]);
            }
            // The PML4 itself last. It is not in `owned` (that list is the tables *below* the
            // root, plus the process's own PDPT), and leaving it out was a one-frame leak per
            // address space - small enough to survive a demonstration, large enough to matter to
            // a machine that is supposed to run for weeks.
            free_frame(self.cr3);
        }
        // Flush the TLB *after* the frames are gone. With PGE enabled a stale translation would
        // survive the next `cr3` write for global pages, and this space has none — but a frame
        // address reused for a new space would make the two CR3 values equal, and the CPU then
        // skips the flush that normally covers this.
        unsafe { cpu::write_cr3(cpu::read_cr3()) };
    }
}

// --------------------------------------------------------------------------- self-test

pub struct PagingReport {
    pub passed: u32,
    pub failed: u32,
    pub failures: alloc::vec::Vec<&'static str>,
}

impl PagingReport {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            failures: alloc::vec::Vec::new(),
        }
    }

    fn check(&mut self, condition: bool, failure: &'static str) {
        if condition {
            self.passed += 1;
        } else {
            self.failed += 1;
            self.failures.push(failure);
        }
    }
}

/// Builds two spaces, maps the same virtual addresses in both, and proves the four properties
/// the isolation claim needs: distinct roots, distinct frames for the same address, a kernel
/// mapping that exists but is not user-reachable, and frames that come back on teardown.
pub fn self_test() -> PagingReport {
    let mut report = PagingReport::new();
    report.check(ready(), "paging was not initialised");

    let baseline = frames_in_use();
    let mut alpha = AddressSpace::new("probe-alpha");
    let mut beta = AddressSpace::new("probe-beta");

    let alpha_frame = alloc_frame();
    let beta_frame = alloc_frame();
    let same_virtual = USER_BASE + 0x1000;

    report.check(
        alpha.map_page(same_virtual, alpha_frame, USER_RW),
        "alpha could not map its page",
    );
    report.check(
        beta.map_page(same_virtual, beta_frame, USER_RW),
        "beta could not map its page",
    );

    report.check(alpha.cr3 != beta.cr3, "both spaces share one PML4");
    report.check(
        alpha.cr3 != kernel_cr3() && beta.cr3 != kernel_cr3(),
        "a process space reuses the kernel's cr3",
    );

    let alpha_walk = alpha.translate(same_virtual);
    let beta_walk = beta.translate(same_virtual);
    report.check(
        matches!(alpha_walk, Some(ref walk) if walk.phys & !(PAGE_SIZE - 1) == alpha_frame),
        "alpha's address does not resolve to alpha's frame",
    );
    report.check(
        matches!(beta_walk, Some(ref walk) if walk.phys & !(PAGE_SIZE - 1) == beta_frame),
        "beta's address does not resolve to beta's frame",
    );
    if let (Some(alpha_walk), Some(beta_walk)) = (alpha_walk, beta_walk) {
        report.check(
            alpha_walk.phys != beta_walk.phys,
            "the same virtual address maps to the same frame in both spaces",
        );
        report.check(
            alpha_walk.user_reachable && beta_walk.user_reachable,
            "a user page is not reachable from CPL 3",
        );
    }

    // The peer window: mapped in beta, absent in alpha. This is the mapping a process in the
    // other space would have to reach in order to read its neighbour.
    let peer_virtual = USER_BASE + 0x20_0000;
    report.check(
        beta.map_page(peer_virtual, beta_frame, USER_RW),
        "beta could not map its peer window",
    );
    report.check(
        alpha.translate(peer_virtual).is_none(),
        "alpha sees a page it never mapped",
    );

    // The kernel branch: present everywhere, reachable from nowhere in ring 3.
    let kernel_probe = crate::bootinfo::KERNEL_LOAD_BASE;
    report.check(
        walk(alpha.cr3, kernel_probe).is_some(),
        "the kernel is not mapped in a process space",
    );
    report.check(
        matches!(walk(alpha.cr3, kernel_probe), Some(walk) if !walk.user_reachable),
        "the kernel identity mapping is reachable from CPL 3",
    );
    report.check(
        alpha.copy_from_user(kernel_probe, &mut [0u8; 8]).is_none(),
        "copy_from_user accepted a supervisor address",
    );
    let mut buffer = [0u8; 8];
    report.check(
        alpha
            .copy_from_user(same_virtual, &mut buffer)
            .map(|read| read == 8)
            .unwrap_or(false),
        "copy_from_user rejected a user page it had just mapped",
    );

    // Remapping: a removed page has to disappear from the walk, not just from the TLB.
    report.check(
        alpha.unmap_page(same_virtual),
        "unmap_page reported nothing to unmap",
    );
    report.check(
        alpha.translate(same_virtual).is_none(),
        "an unmapped page is still translated",
    );

    alpha.teardown();
    beta.teardown();
    report.check(
        frames_in_use() == baseline,
        "address-space teardown did not return every frame",
    );
    report
}
