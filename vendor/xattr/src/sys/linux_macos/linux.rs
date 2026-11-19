use libc::{c_char, c_int, c_void, size_t, ssize_t};

extern "C" {
    pub(super) fn flistxattr(fd: c_int, buf: *mut c_char, size: size_t) -> ssize_t;
    pub(super) fn fgetxattr(fd: c_int, name: *const c_char, value: *mut c_void, size: size_t) -> ssize_t;
    pub(super) fn fremovexattr(fd: c_int, name: *const c_char) -> c_int;

    pub(super) fn llistxattr(path: *const c_char, buf: *mut c_char, size: size_t) -> ssize_t;
    pub(super) fn lgetxattr(
        path: *const c_char,
        name: *const c_char,
        value: *mut c_void,
        size: size_t,
    ) -> ssize_t;
    pub(super) fn lremovexattr(path: *const c_char, name: *const c_char) -> c_int;
}

pub(super) unsafe fn fsetxattr(
    fd: c_int,
    name: *const c_char,
    value: *const c_void,
    size: size_t,
) -> ssize_t {
    extern "C" {
        fn fsetxattr(
            fd: c_int,
            name: *const c_char,
            value: *const c_void,
            size: size_t,
            flags: c_int,
        ) -> ssize_t;
    }
    // SAFETY: The caller supplies a live C string for the name and a readable buffer of size bytes.
    unsafe { fsetxattr(fd, name, value, size, 0) }
}

pub(super) unsafe fn lsetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: size_t,
) -> ssize_t {
    extern "C" {
        fn lsetxattr(
            path: *const c_char,
            name: *const c_char,
            value: *const c_void,
            size: size_t,
            flags: c_int,
        ) -> ssize_t;
    }
    // SAFETY: The caller supplies live C strings for the path and name and a readable buffer of size bytes.
    unsafe { lsetxattr(path, name, value, size, 0) }
}
