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

pub(crate) use control::{requested_from_env, CaptureSetup};
pub(crate) use device::SystemTun;
pub(crate) use registry::{
    KernelCaptureRuntime, KernelIngressBinding, KernelReadBinding, OriginalFullObservation,
};
#[cfg(any(target_os = "linux", all(unix, test)))]
pub(crate) use registry::{
    OriginalKernelCurrentOwners, OriginalKernelExchange, OriginalKernelOnce,
};

#[cfg(any(target_os = "linux", all(unix, test)))]
pub(crate) fn original_kernel_monotonic_ns() -> Option<u64> {
    clock::monotonic_ns()
}

#[cfg(test)]
mod tests;
