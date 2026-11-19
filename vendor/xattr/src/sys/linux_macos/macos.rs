use libc::{c_char, c_int, c_void, size_t, ssize_t};

const XATTR_NOFOLLOW: c_int = 0x0001;

#[inline(always)]
pub(super) unsafe fn fremovexattr(fd: c_int, name: *const c_char) -> c_int {
    extern "C" {
        fn fremovexattr(fd: c_int, name: *const c_char, options: c_int) -> c_int;
    }
    // SAFETY: The caller supplies a live C string for the name.
    unsafe { fremovexattr(fd, name, 0) }
}

#[inline(always)]
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
            position: u32,
            options: c_int,
        ) -> ssize_t;
    }
    // SAFETY: The caller supplies a live C string for the name and a readable buffer of size bytes.
    unsafe { fsetxattr(fd, name, value, size, 0, 0) }
}

#[inline(always)]
pub(super) unsafe fn fgetxattr(
    fd: c_int,
    name: *const c_char,
    value: *mut c_void,
    size: size_t,
) -> ssize_t {
    extern "C" {
        fn fgetxattr(
            fd: c_int,
            name: *const c_char,
            value: *mut c_void,
            size: size_t,
            position: u32,
            options: c_int,
        ) -> ssize_t;
    }
    // SAFETY: The caller supplies a live C string for the name and a writable buffer of size bytes or a null size probe.
    unsafe { fgetxattr(fd, name, value, size, 0, 0) }
}

#[inline(always)]
pub(super) unsafe fn flistxattr(fd: c_int, buf: *mut c_char, size: size_t) -> ssize_t {
    extern "C" {
        fn flistxattr(fd: c_int, buf: *mut c_char, size: size_t, options: c_int) -> ssize_t;
    }
    // SAFETY: The caller supplies a writable buffer of size bytes or a null size probe.
    unsafe { flistxattr(fd, buf, size, 0) }
}

#[inline(always)]
pub(super) unsafe fn lremovexattr(path: *const c_char, name: *const c_char) -> c_int {
    extern "C" {
        fn removexattr(path: *const c_char, name: *const c_char, options: c_int) -> c_int;
    }
    // SAFETY: The caller supplies live C strings for the path and name.
    unsafe { removexattr(path, name, XATTR_NOFOLLOW) }
}

#[inline(always)]
pub(super) unsafe fn lsetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: size_t,
) -> ssize_t {
    extern "C" {
        fn setxattr(
            path: *const c_char,
            name: *const c_char,
            value: *const c_void,
            size: size_t,
            position: u32,
            options: c_int,
        ) -> ssize_t;
    }
    // SAFETY: The caller supplies live C strings for the path and name and a readable buffer of size bytes.
    unsafe { setxattr(path, name, value, size, 0, XATTR_NOFOLLOW) }
}

#[inline(always)]
pub(super) unsafe fn lgetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: size_t,
) -> ssize_t {
    extern "C" {
        fn getxattr(
            path: *const c_char,
            name: *const c_char,
            value: *mut c_void,
            size: size_t,
            position: u32,
            options: c_int,
        ) -> ssize_t;
    }
    // SAFETY: The caller supplies live C strings for the path and name and a writable buffer of size bytes or a null size probe.
    unsafe { getxattr(path, name, value, size, 0, XATTR_NOFOLLOW) }
}

#[inline(always)]
pub(super) unsafe fn llistxattr(path: *const c_char, buf: *mut c_char, size: size_t) -> ssize_t {
    extern "C" {
        fn listxattr(
            path: *const c_char,
            buf: *mut c_char,
            size: size_t,
            options: c_int,
        ) -> ssize_t;
    }
    // SAFETY: The caller supplies a live C string for the path and a writable buffer of size bytes or a null size probe.
    unsafe { listxattr(path, buf, size, XATTR_NOFOLLOW) }
}
