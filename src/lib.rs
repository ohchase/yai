use log::{error, info, trace};
use std::{ffi::c_void, path::Path};
use sysinfo::{Pid, PidExt};
use thiserror::Error;
use windows_sys::{
    core::PCSTR,
    s,
    Win32::{
        Foundation::{CloseHandle, FALSE, HANDLE, HMODULE},
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_DECOMMIT, PAGE_READWRITE},
            Threading::{
                CreateRemoteThread, OpenProcess, WaitForSingleObject, INFINITE,
                PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
            },
        },
    },
};

type LoadLibraryA = unsafe extern "system" fn(lplibfilename: PCSTR) -> HMODULE;

#[derive(Error, Debug)]
pub enum InjectorError {
    #[error("Payload does not exist: `{0}`")]
    PayloadMissing(String),
    #[error("Payload location unable to be initialized as a CString: `{0}`")]
    PayloadCString(#[from] std::ffi::NulError),
    #[error("Payload location unable to be canonicalized: `{0}`")]
    PayloadCanonicalization(#[from] std::io::Error),
    #[error("Process is not active: `{0}`")]
    ProcessNotActive(String),
    #[error("Unable to obtain handle to Kernel32 Module")]
    KernelModule(),
    #[error("Unable to obtain handle to LoadLibrary Proc")]
    LoadLibraryProc(),
    #[error("Unable to open process")]
    ProcessOpen(),
    #[error("Unable to allocate memory in target process")]
    AllocationFailure(),
    #[error("Unable to write specified memory")]
    WriteFailure(),
    #[error("Unable to spawn remote thread")]
    RemoteThread(),
}

/// Injects the payload pointed to by `payload_location` into `pid`.
pub fn inject_into(
    payload_location: impl AsRef<Path>,
    pid: impl Into<Pid>,
) -> Result<(), InjectorError> {
    let payload_location = match std::fs::canonicalize(payload_location) {
        Ok(p) => p.to_str().unwrap().replace("\\\\?\\", ""),
        Err(e) => return Err(InjectorError::PayloadCanonicalization(e)),
    };
    let pid = pid.into();

    info!(
        "Injecting Payload: {:#?} into Pid: {}",
        payload_location, pid
    );

    let kernel_module = get_kernel_module()?;
    info!("Identified kernel module: {:#?}", kernel_module);

    let load_library_proc = get_load_library_proc(kernel_module)?;
    info!(
        "Identified load library proc: {:#?}",
        load_library_proc as *const usize
    );

    let raw_process = RawProcess::open(pid)?;
    let write_size = payload_location.len() + 1;
    let raw_allocation = raw_process.allocate(write_size, MEM_COMMIT, PAGE_READWRITE)?;

    let payload_cstring = match std::ffi::CString::new(payload_location) {
        Ok(cstring) => cstring,
        Err(err) => {
            error!("Unable to create CString from payload absolute path");
            return Err(InjectorError::PayloadCString(err));
        }
    };
    raw_allocation.write(payload_cstring.as_ptr() as *mut c_void)?;
    raw_allocation.spawn_thread_with_args(load_library_proc)?;

    Ok(())
}

struct ContextedRemoteThread<'process> {
    _process: &'process RawProcess,
    thread: HANDLE,
}

impl<'process> ContextedRemoteThread<'process> {
    fn spawn_with_args(
        process: &'process RawProcess,
        allocation: &'process RawAllocation,
        entry_function: LoadLibraryA,
    ) -> Result<Self, InjectorError> {
        let thread = unsafe {
            CreateRemoteThread(
                process.inner(),
                std::ptr::null_mut(),
                0,
                // Transmute from 'fn (*const u8) -> isize' to 'fn(*mut c_void) -> u32'.
                Some(std::mem::transmute(entry_function)),
                allocation.inner(),
                0,
                std::ptr::null_mut(),
            )
        };

        if thread == 0 {
            return Err(InjectorError::RemoteThread());
        }

        Ok(ContextedRemoteThread {
            _process: process,
            thread,
        })
    }
}

impl<'process> Drop for ContextedRemoteThread<'process> {
    fn drop(&mut self) {
        trace!("Closing thread handle");
        unsafe {
            WaitForSingleObject(self.thread, INFINITE);
            CloseHandle(self.thread);
        };
    }
}

struct RawAllocation<'process> {
    process: &'process RawProcess,
    allocation: *mut c_void,
    size: usize,
}

impl<'process> RawAllocation<'process> {
    fn allocate(
        process: &'process RawProcess,
        size: usize,
        allocation_flags: u32,
        protection_flags: u32,
    ) -> Result<Self, InjectorError> {
        let allocation = unsafe {
            VirtualAllocEx(
                process.inner(),
                std::ptr::null_mut(),
                size,
                allocation_flags,
                protection_flags,
            )
        };

        if allocation.is_null() {
            return Err(InjectorError::AllocationFailure());
        }

        trace!(
            "Allocated n bytes: {}, with allocation_flags: {}, and protection_flags: {}",
            size,
            allocation_flags,
            protection_flags
        );

        Ok(RawAllocation {
            process,
            allocation,
            size,
        })
    }

    fn spawn_thread_with_args(
        &self,
        entry_function: LoadLibraryA,
    ) -> Result<ContextedRemoteThread, InjectorError> {
        ContextedRemoteThread::spawn_with_args(self.process, self, entry_function)
    }

    fn inner(&self) -> *mut c_void {
        self.allocation
    }

    fn write(&self, buffer: *mut c_void) -> Result<usize, InjectorError> {
        let mut bytes_written: usize = 0;

        let write_result = unsafe {
            WriteProcessMemory(
                self.process.inner(),
                self.allocation,
                buffer,
                self.size,
                &mut bytes_written,
            )
        };

        if write_result == 0 || bytes_written == 0 {
            return Err(InjectorError::WriteFailure());
        }

        trace!(
            "Wrote n bytes: {} for allocation of size: {}",
            bytes_written,
            self.size
        );

        Ok(bytes_written)
    }
}

impl<'process> Drop for RawAllocation<'process> {
    fn drop(&mut self) {
        trace!("Dropping allocated data");
        unsafe {
            VirtualFreeEx(
                self.process.inner(),
                self.allocation,
                self.size,
                MEM_DECOMMIT,
            );
        }
    }
}

struct RawProcess {
    handle: HANDLE,
}

impl RawProcess {
    fn open(pid: Pid) -> Result<Self, InjectorError> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                FALSE,
                pid.as_u32(),
            )
        };

        if handle == 0 {
            return Err(InjectorError::ProcessOpen());
        }

        Ok(Self { handle })
    }

    fn allocate(
        &self,
        size: usize,
        allocation_flags: u32,
        protection_flags: u32,
    ) -> Result<RawAllocation, InjectorError> {
        RawAllocation::allocate(self, size, allocation_flags, protection_flags)
    }

    fn inner(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for RawProcess {
    fn drop(&mut self) {
        trace!("Dropping Process Handle");
        unsafe {
            CloseHandle(self.handle as HANDLE);
        }
    }
}

fn get_kernel_module() -> Result<HMODULE, InjectorError> {
    let kernel_module = unsafe { GetModuleHandleA(s!("kernel32.dll")) };

    if kernel_module == 0 {
        return Err(InjectorError::KernelModule());
    }

    Ok(kernel_module)
}

fn get_load_library_proc(kernel_module: HMODULE) -> Result<LoadLibraryA, InjectorError> {
    let load_library_proc = unsafe { GetProcAddress(kernel_module, s!("LoadLibraryA")) }
        .ok_or(InjectorError::LoadLibraryProc())?;

    let load_library_proc: LoadLibraryA = unsafe { std::mem::transmute(load_library_proc) };

    Ok(load_library_proc)
}
