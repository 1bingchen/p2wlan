//! Default-disabled registration and sealed system-read observations.
//!
//! Registration labels are not read/send/current-owner authority. A sealed
//! read binding is minted only by the concrete device wrapper after a real
//! successful read. These observations do not consume connection credit.

mod clock;
mod control;
mod device;
mod plan;
mod registry;

pub(crate) use control::CaptureSetup;
pub(crate) use device::SystemTun;
pub(crate) use registry::KernelReadBinding;

#[cfg(test)]
mod tests;
