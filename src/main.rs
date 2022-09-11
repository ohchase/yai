use clap::Parser;
use sysinfo::{Pid, PidExt, ProcessExt, System, SystemExt};
use thiserror::Error;
use winapi::{
    ctypes::c_void,
    shared::minwindef::{FALSE, HMODULE},
    um::{
        handleapi::CloseHandle,
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory},
        processthreadsapi::{CreateRemoteThread, OpenProcess},
        synchapi::WaitForSingleObject,
        winbase::INFINITE,
        winnt::{
            HANDLE, MEM_COMMIT, MEM_DECOMMIT, PAGE_READWRITE, PROCESS_CREATE_THREAD,
            PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
        },
    },
};

#[macro_use]
extern crate log;

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

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(
    name = "yai",
    version = "0.1.3",
    about = "Yet Another Injector for windows x64 dlls."
)]
struct Args {
    /// Process name to inject into
    #[clap(short, long, value_parser)]
    target: String,

    /// Relative path to payload dll
    #[clap(short, long, value_parser)]
    payload: String,
}

struct ContextedRemoteThread<'process> {
    _process: &'process RawProcess,
    thread: *mut c_void,
}

impl<'process> ContextedRemoteThread<'process> {
    fn spawn_with_args(
        process: &'process RawProcess,
        allocation: &'process RawAllocation,
        entry_function: unsafe extern "system" fn(*mut c_void) -> u32,
    ) -> Result<Self, InjectorError> {
        let thread = unsafe {
            CreateRemoteThread(
                process.inner(),
                std::ptr::null_mut(),
                0,
                Some(entry_function),
                allocation.inner(),
                0,
                std::ptr::null_mut(),
            )
        };

        if thread.is_null() {
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
        entry_function: unsafe extern "system" fn(*mut c_void) -> u32,
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

        if handle.is_null() {
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
    let kernel_module = unsafe { GetModuleHandleA("kernel32.dll\0".as_ptr() as *const i8) };

    if kernel_module.is_null() {
        return Err(InjectorError::KernelModule());
    }

    Ok(kernel_module)
}

fn get_load_library_proc(
    kernel_module: HMODULE,
) -> Result<unsafe extern "system" fn(*mut c_void) -> u32, InjectorError> {
    let load_library_proc =
        unsafe { GetProcAddress(kernel_module, "LoadLibraryA\0".as_ptr() as *const i8) };
    if load_library_proc.is_null() {
        return Err(InjectorError::LoadLibraryProc());
    }

    let load_library_proc: unsafe extern "system" fn(*mut c_void) -> u32 =
        unsafe { std::mem::transmute(load_library_proc) };

    Ok(load_library_proc)
}

fn main() -> Result<(), InjectorError> {
    std::env::set_var("RUST_LOG", "trace");
    pretty_env_logger::init();

    let args = Args::parse();
    let process_name = &args.target;
    let payload_location = &args.payload;

    let mut current_dir = std::env::current_dir()?;
    current_dir.push(payload_location);
    let payload_location = current_dir.as_path();

    match payload_location.exists() {
        true => {}
        false => {
            error!("Payload does not exist");
            return Err(InjectorError::PayloadMissing(args.payload));
        }
    }

    let payload_location = match std::fs::canonicalize(payload_location) {
        Ok(p) => p.to_str().unwrap().replace("\\\\?\\", ""),
        Err(e) => return Err(InjectorError::PayloadCanonicalization(e)),
    };

    let mut sys = System::new_all();
    sys.refresh_processes();
    let process = sys.processes_by_name(process_name).next();

    let process = match process {
        Some(process) => process,
        None => {
            error!("Process does not exist/is not actively running");
            return Err(InjectorError::ProcessNotActive(args.target));
        }
    };

    info!(
        "Injecting Payload: {:#?} into Process: {}",
        payload_location, process_name
    );

    let kernel_module = get_kernel_module()?;
    info!("Identified kernel module: {:#?}", kernel_module);

    let load_library_proc = get_load_library_proc(kernel_module)?;
    info!(
        "Identified load library proc: {:#?}",
        load_library_proc as *const usize
    );

    let raw_process = RawProcess::open(process.pid())?;
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
