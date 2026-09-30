//! The block layer: one interface for anything that stores 512-byte sectors.
//!
//! Everything above this module — the persistent vault, its on-disk format, its unlock gate —
//! is written against [`BlockDevice`] and never against a controller. That is not decoration:
//! it is what makes the storage format testable without hardware (see [`MemDisk`]), and it is
//! what keeps the vault from depending on which disk happens to be plugged in.
//!
//! **Sectors are 512 bytes and the interface says so.** Every real device on this machine is
//! 512-byte addressed (the AHCI driver can report otherwise and refuses to drive such a device
//! rather than silently mis-addressing it), and a layer that accepted arbitrary sizes would push
//! the remainder arithmetic into every caller. A buffer whose length is not a whole number of
//! sectors is refused with [`BlockError::BadLength`]; a request past the end of the device is
//! refused with [`BlockError::OutOfRange`] *before* a command is built, so the driver never has
//! to work out what a partial transfer past the end means.
//!
//! **Failures are answers, not panics.** A write that the device rejected has to reach the
//! caller as an error, because the persistent vault's whole job is to not claim that data is on
//! disk when it is not. [`MemDisk`] therefore has a fault-injection hook, and the self-test uses
//! it: a disk that lies about a write is a disk whose caller must notice.

use crate::crypto;
use alloc::vec::Vec;

/// The only sector size this layer addresses.
pub const SECTOR_SIZE: usize = 512;
/// Sectors per KiB, for the geometry lines.
pub const SECTORS_PER_KIB: u64 = 1024 / SECTOR_SIZE as u64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockError {
    /// No device on this interface.
    NotPresent,
    /// The buffer is not a whole number of sectors, or is empty.
    BadLength,
    /// The request runs past the end of the device.
    OutOfRange,
    /// The device reported a failure for a command it was given.
    DeviceError,
    /// The device did not complete a command inside the driver's budget.
    Timeout,
    /// The device answered, but not with something this layer can use.
    Unsupported,
}

impl BlockError {
    pub fn as_str(self) -> &'static str {
        match self {
            BlockError::NotPresent => "no-device",
            BlockError::BadLength => "bad-length",
            BlockError::OutOfRange => "out-of-range",
            BlockError::DeviceError => "device-error",
            BlockError::Timeout => "timeout",
            BlockError::Unsupported => "unsupported",
        }
    }
}

/// A device that reads and writes 512-byte sectors.
///
/// Implementations must reject a request they cannot serve *before* touching the medium, and must
/// not report success for a transfer that did not happen.
pub trait BlockDevice {
    /// Sectors the device can address.
    fn sector_count(&self) -> u64;

    /// Fills `buffer` (a whole number of sectors) from `lba`.
    fn read_sectors(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError>;

    /// Writes `buffer` (a whole number of sectors) at `lba`.
    fn write_sectors(&mut self, lba: u64, buffer: &[u8]) -> Result<(), BlockError>;
}

/// True when a length is a non-empty whole number of sectors.
pub fn is_segment_aligned(length: usize) -> bool {
    length != 0 && length % SECTOR_SIZE == 0
}

/// True when the buffer is a non-empty whole number of sectors.
pub fn is_sector_aligned(buffer: &[u8]) -> bool {
    is_segment_aligned(buffer.len())
}

/// Which sector a byte offset lands in.
pub fn sector_of(offset: u64) -> u64 {
    offset / SECTOR_SIZE as u64
}

/// Shared argument checking, so every implementation refuses the same things the same way.
///
/// Returns the number of sectors the request covers.
pub fn validate(sector_count: u64, lba: u64, length: usize) -> Result<u64, BlockError> {
    if !is_segment_aligned(length) {
        return Err(BlockError::BadLength);
    }
    let sectors = (length / SECTOR_SIZE) as u64;
    // Written as a range check on the *end* rather than two separate tests: `lba >= sector_count`
    // is implied by `lba + sectors > sector_count` for a non-empty request, and the addition
    // cannot overflow because both terms are bounded by a device's sector count.
    if lba.checked_add(sectors).map(|end| end > sector_count).unwrap_or(true) {
        return Err(BlockError::OutOfRange);
    }
    Ok(sectors)
}

// ------------------------------------------------------------------------------------ MemDisk

/// A disk in ordinary memory: the block layer's reference implementation and its test fixture.
///
/// It exists for two reasons. The storage format can be exercised on every machine, including
/// one with no controller at all, so a boot with no disk still proves the format, the checksum
/// and the unlock gate. And it can be told to fail on purpose: `fail_writes_after(n)` makes the
/// *n*-th write return [`BlockError::DeviceError`] without storing anything, which is how the
/// self-test proves that a rejected write is reported instead of believed.
pub struct MemDisk {
    data: Vec<u8>,
    reads: u64,
    writes: u64,
    errors: u64,
    /// Writes left before every write fails; `None` means the disk works.
    fail_writes_after: Option<u64>,
}

impl MemDisk {
    /// A zeroed disk of `sectors` sectors.
    pub fn new(sectors: u64) -> Self {
        let mut data = Vec::new();
        data.resize(sectors as usize * SECTOR_SIZE, 0);
        Self {
            data,
            reads: 0,
            writes: 0,
            errors: 0,
            fail_writes_after: None,
        }
    }

    /// A disk whose medium is the given bytes. Used by the storage layer's tamper cases: an image
    /// with one byte changed is a disk, not a special case.
    pub fn from_bytes(contents: &[u8]) -> Self {
        let mut data = Vec::from(contents);
        if data.len() % SECTOR_SIZE != 0 {
            data.resize(data.len() + (SECTOR_SIZE - data.len() % SECTOR_SIZE), 0);
        }
        Self {
            data,
            reads: 0,
            writes: 0,
            errors: 0,
            fail_writes_after: None,
        }
    }

    /// Fails every write after the first `allowed` ones, simulating a device that has run out of
    /// media or a controller that has dropped off the bus.
    pub fn fail_writes_after(&mut self, allowed: u64) {
        self.fail_writes_after = Some(allowed);
    }

    pub fn reads(&self) -> u64 {
        self.reads
    }

    pub fn writes(&self) -> u64 {
        self.writes
    }

    pub fn errors(&self) -> u64 {
        self.errors
    }

    /// Raw access for tests that want to inspect the medium behind the interface.
    pub fn peek(&self, offset: usize, length: usize) -> &[u8] {
        &self.data[offset..offset + length]
    }

    /// Wipes the medium the way a panic scrub does, and counts it as an error-free operation.
    pub fn scrub(&mut self) {
        crypto::wipe(&mut self.data);
    }
}

impl BlockDevice for MemDisk {
    fn sector_count(&self) -> u64 {
        (self.data.len() / SECTOR_SIZE) as u64
    }

    fn read_sectors(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        let sectors = validate(self.sector_count(), lba, buffer.len())?;
        let start = lba as usize * SECTOR_SIZE;
        buffer.copy_from_slice(&self.data[start..start + sectors as usize * SECTOR_SIZE]);
        self.reads += 1;
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        let sectors = validate(self.sector_count(), lba, buffer.len())?;
        if let Some(remaining) = self.fail_writes_after {
            if remaining == 0 {
                // Nothing is stored: a device that failed a write must leave no trace of it.
                self.errors += 1;
                return Err(BlockError::DeviceError);
            }
            self.fail_writes_after = Some(remaining - 1);
        }
        let start = lba as usize * SECTOR_SIZE;
        self.data[start..start + sectors as usize * SECTOR_SIZE].copy_from_slice(buffer);
        self.writes += 1;
        Ok(())
    }
}

// ------------------------------------------------------------------------------------ self-test

pub struct BlockReport {
    pub passed: u32,
    pub failed: u32,
    /// Assertions that need a real controller. A machine with no disk still runs every check the
    /// in-memory device can answer.
    pub skipped: u32,
    pub failures: Vec<&'static str>,
}

impl BlockReport {
    pub fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            skipped: 0,
            failures: Vec::new(),
        }
    }

    pub fn check(&mut self, condition: bool, failure: &'static str) {
        if condition {
            self.passed += 1;
        } else {
            self.failed += 1;
            self.failures.push(failure);
        }
    }

    pub fn skip(&mut self, count: u32) {
        self.skipped += count;
    }
}

/// Exercises the block layer against [`MemDisk`]: geometry, a verified round trip, every refusal
/// this layer defines, and a device that fails a write on purpose.
pub fn self_test() -> BlockReport {
    let mut report = BlockReport::new();
    let mut disk = MemDisk::new(64);
    report.check(disk.sector_count() == 64, "the disk's sector count is not what it was built with");

    // A round trip through the interface.
    let mut pattern = [0u8; SECTOR_SIZE * 2];
    for (index, byte) in pattern.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(7).wrapping_add(3);
    }
    report.check(disk.write_sectors(3, &pattern).is_ok(), "a legal write was refused");
    let mut readback = [0u8; SECTOR_SIZE * 2];
    report.check(disk.read_sectors(3, &mut readback).is_ok(), "a legal read was refused");
    report.check(readback == pattern, "the round trip did not return what was written");
    report.check(
        disk.writes() == 1 && disk.reads() == 1,
        "the disk's own counters do not match the operations it was given",
    );

    // A different sector must be untouched, or the layer is writing outside the request.
    let mut neighbour = [0u8; SECTOR_SIZE];
    report.check(disk.read_sectors(5, &mut neighbour).is_ok(), "a read of the neighbour failed");
    report.check(
        neighbour == [0u8; SECTOR_SIZE],
        "a write touched a sector the caller did not name",
    );

    // Refusals, each with the reason this layer defines for it.
    report.check(
        matches!(disk.read_sectors(63, &mut [0u8; SECTOR_SIZE]), Ok(())),
        "the last sector of the device is not addressable",
    );
    report.check(
        matches!(disk.read_sectors(64, &mut [0u8; SECTOR_SIZE]), Err(BlockError::OutOfRange)),
        "a read at the first sector past the end was not refused",
    );
    report.check(
        matches!(disk.write_sectors(63, &[0u8; SECTOR_SIZE * 2]), Err(BlockError::OutOfRange)),
        "a transfer that runs past the end was not refused",
    );
    report.check(
        matches!(disk.read_sectors(0, &mut [0u8; SECTOR_SIZE - 1]), Err(BlockError::BadLength)),
        "a buffer that is not a whole number of sectors was accepted",
    );
    report.check(
        matches!(disk.read_sectors(0, &mut []), Err(BlockError::BadLength)),
        "an empty transfer was accepted",
    );
    report.check(
        !is_sector_aligned(&[0u8; 1000]) && is_sector_aligned(&[0u8; 1024]),
        "the alignment predicate does not agree with the sector size",
    );
    report.check(sector_of(1024) == 2 && sector_of(1535) == 2, "sector arithmetic is wrong");

    // A device that fails a write must be reported, and must not have stored anything.
    let mut failing = MemDisk::new(8);
    failing.fail_writes_after(1);
    report.check(
        failing.write_sectors(0, &[0xAA; SECTOR_SIZE]).is_ok(),
        "the first write of a working disk was refused",
    );
    report.check(
        matches!(failing.write_sectors(1, &[0xBB; SECTOR_SIZE]), Err(BlockError::DeviceError)),
        "a device that rejected a write was reported as having accepted it",
    );
    let mut untouched = [0u8; SECTOR_SIZE];
    report.check(failing.read_sectors(1, &mut untouched).is_ok(), "the read-back failed");
    report.check(
        untouched == [0u8; SECTOR_SIZE],
        "a write the device rejected still reached the medium",
    );
    report.check(
        failing.errors() == 1 && failing.writes() == 1,
        "the failing disk's counters do not match what it was asked to do",
    );

    report
}
