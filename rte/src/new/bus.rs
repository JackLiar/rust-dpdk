//! Buses: enumeration and global operations.
//!
//! `rte_bus.h` describes process-global bus objects that DPDK registers from
//! library constructors (`RTE_REGISTER_BUS`). This module exposes the
//! *consumption* side of that interface through [`Eal`]:
//!
//! * enumeration — [`Eal::for_each_bus`], [`Eal::bus_by_name`],
//!   [`Eal::bus_by_device`], [`Eal::find_bus`],
//! * global scan/probe — [`Eal::bus_scan`], [`Eal::bus_probe`],
//! * the IOVA class decided across all buses — [`Eal::iommu_class`],
//! * dumping the registered bus names — [`Eal::dump_buses`].
//!
//! [`Bus`] and [`BusDevice`] are `Copy`, non-owning views. Neither has a `Drop`,
//! so it is structurally impossible for safe code to unregister a bus or free a
//! device through them. The lookup entry points borrow the `Eal`, which is what
//! keeps every view from outliving `rte_eal_cleanup()`.
//!
//! ## Deliberate omissions
//!
//! * No wrapper for `rte_bus_register()` / `rte_bus_unregister()`: implementing
//!   a bus in Rust needs capture-less `unsafe extern "C"` callbacks, which is a
//!   different design problem.
//! * No access to `struct rte_bus::next`: the `TAILQ` linkage is owned by DPDK.
//! * The per-bus operation callbacks (`scan`, `plug`, `dma_map`, ...) are not
//!   wrapped; reach them through [`Bus::as_ptr`] if you need them.

use core::ffi::{c_int, c_void};
use core::fmt;
use core::marker::PhantomData;
use core::ops::ControlFlow;
use core::ptr::{self, NonNull};
use std::any::Any;
use std::ffi::{CStr, CString};
use std::os::unix::io::AsRawFd;

use cfile::foreign_types::ForeignType;

use crate::ffi;

use super::eal::Eal;
use super::error::{errno_from_return, rte_strerror, BusError};

/// IOVA mapping mode of a bus (`enum rte_iova_mode`).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IovaMode {
    /// No preference has been expressed.
    DontCare = ffi::rte_iova_mode::RTE_IOVA_DC,
    /// DMA using physical addresses.
    Physical = ffi::rte_iova_mode::RTE_IOVA_PA,
    /// DMA using virtual addresses.
    Virtual = ffi::rte_iova_mode::RTE_IOVA_VA,
}

impl IovaMode {
    /// Map a raw `RTE_IOVA_*` value, folding anything unknown into `DontCare`.
    fn from_raw(raw: ffi::rte_iova_mode::Type) -> Self {
        match raw {
            ffi::rte_iova_mode::RTE_IOVA_PA => Self::Physical,
            ffi::rte_iova_mode::RTE_IOVA_VA => Self::Virtual,
            _ => Self::DontCare,
        }
    }

    /// The `RTE_IOVA_*` value behind this mode.
    #[inline]
    pub fn as_raw(self) -> u32 {
        self as u32
    }
}

/// A borrowed view of a registered `struct rte_bus`.
///
/// It is `Copy` and has no `Drop`, so it can never unregister the bus.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Bus<'a> {
    ptr: NonNull<ffi::rte_bus>,
    _borrow: PhantomData<&'a ()>,
}

// SAFETY: a bus is a process-global handle that is only read from, and the
// underlying `struct rte_bus` is safe to inspect concurrently.
unsafe impl Send for Bus<'_> {}
unsafe impl Sync for Bus<'_> {}

impl<'a> Bus<'a> {
    /// Wrap a raw `rte_bus` pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must point at a bus that stays registered for `'a`. Using a bus
    /// after `rte_eal_cleanup()` is undefined behaviour, so the caller is also
    /// responsible for tying `'a` to the EAL lifetime.
    #[inline]
    pub unsafe fn from_raw(ptr: NonNull<ffi::rte_bus>) -> Bus<'a> {
        Self {
            ptr,
            _borrow: PhantomData,
        }
    }

    /// Raw pointer, for passing back to DPDK.
    #[inline]
    pub fn as_ptr(self) -> NonNull<ffi::rte_bus> {
        self.ptr
    }

    /// Name of the bus, e.g. `"pci"` or `"vdev"`.
    ///
    /// `rte_bus_register()` refuses a NULL or empty name, so this is always a
    /// valid C string for a registered bus.
    #[inline]
    pub fn name(self) -> &'a CStr {
        // SAFETY: DPDK guarantees `name` is set for every registered bus.
        unsafe { CStr::from_ptr((*self.ptr.as_ptr()).name) }
    }
}

impl fmt::Debug for Bus<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bus")
            .field("name", &self.name().to_string_lossy())
            .field("ptr", &self.ptr)
            .finish()
    }
}

/// A borrowed view of an `struct rte_device`.
///
/// Only the fields needed to identify a device are exposed, and there is no
/// `Drop`: this module is about buses, not device hotplug.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct BusDevice<'a> {
    ptr: NonNull<ffi::rte_device>,
    _borrow: PhantomData<&'a ()>,
}

// SAFETY: the view only reads the device's identifying fields.
unsafe impl Send for BusDevice<'_> {}
unsafe impl Sync for BusDevice<'_> {}

impl<'a> BusDevice<'a> {
    /// Wrap a raw `rte_device` pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must point at a live device for `'a`.
    #[inline]
    pub unsafe fn from_raw(ptr: NonNull<ffi::rte_device>) -> BusDevice<'a> {
        Self {
            ptr,
            _borrow: PhantomData,
        }
    }

    /// Raw pointer, for passing back to DPDK.
    #[inline]
    pub fn as_ptr(self) -> NonNull<ffi::rte_device> {
        self.ptr
    }

    /// Name of the device, e.g. `"0000:00:1f.6"` for a PCI device.
    #[inline]
    pub fn name(self) -> &'a CStr {
        // SAFETY: every device DPDK hands out has been named.
        unsafe { CStr::from_ptr((*self.ptr.as_ptr()).name) }
    }
}

impl fmt::Debug for BusDevice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BusDevice")
            .field("name", &self.name().to_string_lossy())
            .field("ptr", &self.ptr)
            .finish()
    }
}

impl Eal {
    /// Scan every registered bus for devices.
    ///
    /// DPDK 20.11 always returns 0 here and only logs a failing bus; the
    /// `Result` mirrors the C prototype and stays correct on versions that
    /// propagate the value.
    pub fn bus_scan(&self) -> Result<(), BusError> {
        let ret = unsafe { ffi::rte_bus_scan() };

        if ret == 0 {
            Ok(())
        } else {
            let errno = errno_from_return(ret);

            Err(BusError::Scan {
                errno,
                message: rte_strerror(errno),
            })
        }
    }

    /// Probe every device on every registered bus.
    ///
    /// Like [`Eal::bus_scan`], DPDK 20.11 always reports success and logs
    /// per-bus failures instead.
    pub fn bus_probe(&self) -> Result<(), BusError> {
        let ret = unsafe { ffi::rte_bus_probe() };

        if ret == 0 {
            Ok(())
        } else {
            let errno = errno_from_return(ret);

            Err(BusError::Probe {
                errno,
                message: rte_strerror(errno),
            })
        }
    }

    /// Look up a registered bus by name.
    ///
    /// A name that cannot be represented as a C string (empty, or containing an
    /// interior NUL) simply cannot match a bus and yields `None`.
    pub fn bus_by_name(&self, name: &str) -> Option<Bus<'_>> {
        let name = CString::new(name).ok()?;

        // SAFETY: `rte_bus_find_by_name()` returns either NULL or a registered
        // bus, which lives at least as long as the EAL this borrow comes from.
        NonNull::new(unsafe { ffi::rte_bus_find_by_name(name.as_ptr()) }).map(|ptr| unsafe { Bus::from_raw(ptr) })
    }

    /// Find the bus a device belongs to.
    ///
    /// Returns `None` when the device has not been claimed by any bus, which is
    /// the normal state before the first scan.
    pub fn bus_by_device(&self, dev: &BusDevice<'_>) -> Option<Bus<'_>> {
        // SAFETY: `dev` is a live device view for the duration of the call.
        let ptr = unsafe { ffi::rte_bus_find_by_device(dev.as_ptr().as_ptr()) };

        // SAFETY: the returned bus is registered and outlives this `&Eal`.
        NonNull::new(ptr).map(|ptr| unsafe { Bus::from_raw(ptr) })
    }

    /// Find the first registered bus for which `cmp` returns `true`.
    ///
    /// A panic raised by `cmp` is caught at the FFI boundary and resumed once
    /// `rte_bus_find()` has returned.
    pub fn find_bus<F>(&self, cmp: F) -> Option<Bus<'_>>
    where
        F: FnMut(&Bus<'_>) -> bool,
    {
        struct Ctx<F> {
            cmp: F,
            panicked: Option<Box<dyn Any + Send>>,
        }

        unsafe extern "C" fn trampoline<F>(bus: *const ffi::rte_bus, data: *const c_void) -> c_int
        where
            F: FnMut(&Bus<'_>) -> bool,
        {
            let ctx = unsafe { &mut *data.cast_mut().cast::<Ctx<F>>() };

            if ctx.panicked.is_some() {
                return 1;
            }

            let Some(ptr) = NonNull::new(bus as *mut ffi::rte_bus) else {
                return 1;
            };

            // SAFETY: DPDK passes a live bus for the duration of the callback,
            // and `Bus` is a non-owning view.
            let view = unsafe { Bus::from_raw(ptr) };

            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (ctx.cmp)(&view))) {
                Ok(true) => 0,
                Ok(false) => 1,
                Err(payload) => {
                    ctx.panicked = Some(payload);

                    1
                }
            }
        }

        let mut ctx = Ctx { cmp, panicked: None };

        // SAFETY: `ctx` outlives the call and is only borrowed by `trampoline`.
        let found = unsafe {
            ffi::rte_bus_find(
                ptr::null::<ffi::rte_bus>(),
                Some(trampoline::<F>),
                &mut ctx as *mut Ctx<F> as *const c_void,
            )
        };

        if let Some(payload) = ctx.panicked {
            std::panic::resume_unwind(payload);
        }

        // SAFETY: the returned bus is registered and outlives this `&Eal`.
        NonNull::new(found).map(|ptr| unsafe { Bus::from_raw(ptr) })
    }

    /// Visit every registered bus until `f` returns [`ControlFlow::Break`].
    ///
    /// Buses are process-global and stay registered while the EAL is alive, so
    /// the walk terminates even though DPDK has no `rte_bus_walk()`: an
    /// always-matching comparator turns `rte_bus_find()`, which resumes *after*
    /// its start argument, into a forward iterator.
    pub fn for_each_bus<F>(&self, mut f: F) -> ControlFlow<()>
    where
        F: FnMut(Bus<'_>) -> ControlFlow<()>,
    {
        unsafe extern "C" fn accept_all(_bus: *const ffi::rte_bus, _data: *const c_void) -> c_int {
            0
        }

        let mut current: *const ffi::rte_bus = ptr::null();

        loop {
            // SAFETY: `current` is either NULL or the bus returned by the
            // previous iteration, which stays registered for the EAL lifetime.
            let next = unsafe { ffi::rte_bus_find(current, Some(accept_all), ptr::null::<c_void>()) };

            let Some(ptr) = NonNull::new(next as *mut ffi::rte_bus) else {
                return ControlFlow::Continue(());
            };

            // SAFETY: `rte_bus_find()` returned a live registered bus.
            if let ControlFlow::Break(()) = f(unsafe { Bus::from_raw(ptr) }) {
                return ControlFlow::Break(());
            }

            current = next;
        }
    }

    /// IOVA class requested across all registered buses.
    ///
    /// [`IovaMode::DontCare`] means no bus expressed a preference, or that the
    /// buses disagree.
    #[inline]
    pub fn iommu_class(&self) -> IovaMode {
        IovaMode::from_raw(unsafe { ffi::rte_bus_get_iommu_class() })
    }

    /// Write the name of every registered bus to an open stream.
    ///
    /// The stream is obtained with `fdopen(3)`, which takes ownership of the
    /// file descriptor: the underlying fd is closed when this function returns.
    pub fn dump_buses<S: AsRawFd>(&self, s: &S) -> Result<(), BusError> {
        let mut f = cfile::fdopen(s, "w")?;

        // SAFETY: `f` is a valid open `FILE *` for the duration of the call.
        unsafe { ffi::rte_bus_dump(f.as_ptr() as *mut ffi::FILE) };

        Ok(())
    }
}
