use std::io;

// Need to use this one as libc only defines this on supported platforms. Given
// that we want to at least compile on unsupported platforms, we define this in
// our platform-specific modules.
use sys::ENOATTR;

#[cfg(any(target_os = "android", target_os = "linux", target_os = "macos"))]
pub(crate) fn name_to_c(name: &std::ffi::OsStr) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    match std::ffi::CString::new(name.as_bytes()) {
        Ok(name) => Ok(name),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "name must not contain null bytes",
        )),
    }
}

pub(crate) fn extract_noattr(result: io::Result<Vec<u8>>) -> io::Result<Option<Vec<u8>>> {
    result.map(Some).or_else(|e| match e.raw_os_error() {
        Some(ENOATTR) => Ok(None),
        _ => Err(e),
    })
}

#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd"
))]
pub(crate) use self::supported::{allocate_loop, path_to_c};

#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd"
))]
mod supported {
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    use libc::{ssize_t, ERANGE};

    pub(crate) fn path_to_c(path: &Path) -> io::Result<CString> {
        match CString::new(path.as_os_str().as_bytes()) {
            Ok(name) => Ok(name),
            Err(_) => Err(io::Error::new(io::ErrorKind::NotFound, "file not found")),
        }
    }

    // The callback must initialize the returned byte count on buffered success,
    // and that count must be within the supplied capacity. A null buffer probes the size.
    pub(crate) unsafe fn allocate_loop<F: FnMut(*mut u8, usize) -> ssize_t>(
        mut f: F,
    ) -> io::Result<Vec<u8>> {
        let mut vec: Vec<u8> = Vec::new();
        loop {
            let ret = (f)(ptr::null_mut(), 0);
            if ret < 0 {
                return Err(io::Error::last_os_error());
            } else if ret == 0 {
                break;
            }
            vec.reserve_exact(ret.cast_unsigned());

            let ret = (f)(vec.as_mut_ptr(), vec.capacity());
            if ret >= 0 {
                // SAFETY: The callback initialized this many bytes within the capacity.
                unsafe { vec.set_len(ret.cast_unsigned()) };
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERANGE) {
                return Err(error);
            }
        }
        vec.shrink_to_fit();
        Ok(vec)
    }
}
