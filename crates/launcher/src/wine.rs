//! Collection of wine-specific functions necessary to fix dubious Proton/Steam code.

use std::{
    ffi::{c_char, CStr, CString},
    ptr,
    sync::LazyLock,
};

use eyre::ContextCompat;
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{
            NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_SUCCESS, STATUS_VARIABLE_NOT_FOUND,
        },
        System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
    },
};

type WineUnixGetEnv = unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> NTSTATUS;
type WineUnixSetEnv = unsafe extern "C" fn(*const c_char, *const c_char) -> NTSTATUS;
type WineGetVersion = extern "C" fn() -> *const c_char;

/// # Safety
///
/// `F` must be a function pointer type with signature matching the exported function.
unsafe fn get_ntdll_export<F: Copy>(name: &CStr) -> Option<F> {
    const {
        assert!(size_of::<F>() == size_of::<usize>());
        assert!(align_of::<F>() == align_of::<usize>());
    };
    unsafe {
        let ntdll = GetModuleHandleA(PCSTR(c"ntdll.dll".as_ptr().cast()))
            .expect("can't get handle to ntdll");

        GetProcAddress(ntdll, PCSTR(name.as_ptr().cast()))
            .map(|proc| std::mem::transmute_copy(&proc))
    }
}

// These are Wine extensions added to Valve's fork used in Proton:
// https://github.com/ValveSoftware/wine/blob/proton_11.0/dlls/ntdll/ntdll.spec#L1758
//
// Although the commits introducing them considered it a "hack", they have been there
// since Proton 9 (8 for SET_ENV) and are likely staying for the foreseeable future.
//
// If they are ever revomed we can always go the route of /proc/self/maps -> libc ->
// pull getenv/setenv from the IAT, but using them is way simpler.
static UNIX_GET_ENV: LazyLock<Option<WineUnixGetEnv>> =
    LazyLock::new(|| unsafe { get_ntdll_export(c"__wine_get_unix_env") });
static UNIX_SET_ENV: LazyLock<Option<WineUnixSetEnv>> =
    LazyLock::new(|| unsafe { get_ntdll_export(c"__wine_set_unix_env") });

// Use wine_get_version as a reliable way to detect if we're on Wine or native
// Windows.
static WINE_GET_VERSION: LazyLock<Option<WineGetVersion>> =
    LazyLock::new(|| unsafe { get_ntdll_export(c"wine_get_version") });

/// Check if this process is running under Wine.
pub fn is_running_wine() -> bool {
    WINE_GET_VERSION.is_some()
}

/// Get the value of a Unix environment variable when under Wine.
fn unix_get_env(var: &CStr) -> eyre::Result<Option<CString>> {
    let getenv = UNIX_GET_ENV.wrap_err("ntdll.__wine_get_unix_env unavailable")?;

    // Call getenv until our buffer is large enough to hold the value.
    let mut buffer: Vec<u8> = Vec::with_capacity(1024);
    loop {
        match unsafe { getenv(var.as_ptr(), buffer.as_mut_ptr().cast(), buffer.capacity()) } {
            STATUS_SUCCESS => unsafe {
                let len = CStr::from_ptr(buffer.as_ptr().cast()).count_bytes();
                buffer.set_len(len + 1);
                break Ok(Some(CString::from_vec_with_nul_unchecked(buffer)));
            },
            STATUS_VARIABLE_NOT_FOUND => break Ok(None),
            STATUS_BUFFER_TOO_SMALL => buffer.reserve(2 * buffer.capacity()),
            err => eyre::bail!("__wine_get_unix_env failed: {err:?}"),
        }
    }
}

/// Set the value of a Unix environment variable when under Wine.
///
/// # Safety
///
/// This is inherently unsafe as setting environment variables on Unix systems
/// is not thread-safe.
unsafe fn unix_set_env(var: &CStr, value: Option<&CStr>) -> eyre::Result<()> {
    let setenv = UNIX_SET_ENV.wrap_err("ntdll.__wine_set_unix_env unavailable")?;
    let status = unsafe {
        setenv(
            var.as_ptr(),
            value.map(|s| s.as_ptr()).unwrap_or(ptr::null()),
        )
    };
    status
        .is_ok()
        .then_some(())
        .wrap_err_with(|| format!("__wine_set_unix_env failed: {status:?}"))
}

/// Guard struct that allows temporarily setting a Unix environment variable.
pub struct UnixEnvGuard {
    var: CString,
    original_value: Option<CString>,
}

impl UnixEnvGuard {
    /// Create an env guard setting `var` to `value`.
    ///
    /// # Safety
    ///
    /// This is inherently unsafe as setting environment variables on Unix systems
    /// is not thread-safe.
    pub unsafe fn new(var: impl Into<CString>, value: Option<&CStr>) -> eyre::Result<Self> {
        let var = var.into();
        let original_value = unix_get_env(&var)?;
        unsafe { unix_set_env(&var, value) }?;
        Ok(Self {
            var,
            original_value,
        })
    }
}

impl Drop for UnixEnvGuard {
    fn drop(&mut self) {
        if let Err(e) = unsafe { unix_set_env(&self.var, self.original_value.as_deref()) } {
            tracing::error!("failed to reset env var: {e}")
        }
    }
}
