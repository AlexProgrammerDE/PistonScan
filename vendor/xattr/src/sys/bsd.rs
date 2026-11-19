//! FreeBSD and NetBSD xattr support.

#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::convert::TryFrom;
use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::mem;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::RawFd;
use std::path::Path;

use libc::{c_char, c_int, c_void, size_t, ssize_t, EPERM};
use util::{allocate_loop, path_to_c};

const EXTATTR_NAMESPACE_USER_STRING: &str = "user";
const EXTATTR_NAMESPACE_SYSTEM_STRING: &str = "system";
const EXTATTR_NAMESPACE_NAMES: [&str; 3] = [
    "empty",
    EXTATTR_NAMESPACE_USER_STRING,
    EXTATTR_NAMESPACE_SYSTEM_STRING,
];
const EXTATTR_NAMESPACE_USER: c_int = 1;
const EXTATTR_NAMESPACE_SYSTEM: c_int = 2;

extern "C" {
    fn extattr_list_fd(
        fd: c_int,
        attrnamespace: c_int,
        data: *mut c_void,
        nbytes: size_t,
    ) -> ssize_t;
    fn extattr_get_fd(
        fd: c_int,
        attrnamespace: c_int,
        attrname: *const c_char,
        data: *mut c_void,
        nbytes: size_t,
    ) -> ssize_t;
    fn extattr_delete_fd(fd: c_int, attrname: c_int, attrname: *const c_char) -> c_int;
    fn extattr_set_fd(
        fd: c_int,
        attrname: c_int,
        attrname: *const c_char,
        data: *const c_void,
        nbytes: size_t,
    ) -> ssize_t;

    fn extattr_list_link(
        path: *const c_char,
        attrnamespace: c_int,
        data: *mut c_void,
        nbytes: size_t,
    ) -> ssize_t;
    fn extattr_get_link(
        path: *const c_char,
        attrnamespace: c_int,
        attrname: *const c_char,
        data: *mut c_void,
        nbytes: size_t,
    ) -> ssize_t;
    fn extattr_delete_link(
        path: *const c_char,
        attrname: c_int,
        attrname: *const c_char,
    ) -> c_int;
    fn extattr_set_link(
        path: *const c_char,
        attrname: c_int,
        attrname: *const c_char,
        data: *const c_void,
        nbytes: size_t,
    ) -> ssize_t;
}

/// An iterator over a set of extended attributes names.
#[derive(Debug)]
pub struct XAttrs {
    user_attrs: Box<[u8]>,
    system_attrs: Box<[u8]>,
    offset: usize,
}

impl Clone for XAttrs {
    fn clone(&self) -> Self {
        Self {
            user_attrs: Vec::from(&*self.user_attrs).into_boxed_slice(),
            system_attrs: Vec::from(&*self.system_attrs).into_boxed_slice(),
            offset: self.offset,
        }
    }

    fn clone_from(&mut self, other: &Self) {
        self.offset = other.offset;

        let mut data = mem::replace(&mut self.user_attrs, Box::new([])).into_vec();
        data.extend(other.user_attrs.iter().copied());
        self.user_attrs = data.into_boxed_slice();

        data = mem::replace(&mut self.system_attrs, Box::new([])).into_vec();
        data.extend(other.system_attrs.iter().copied());
        self.system_attrs = data.into_boxed_slice();
    }
}

impl Iterator for XAttrs {
    type Item = OsString;
    fn next(&mut self) -> Option<OsString> {
        let system_len = self.system_attrs.len();
        let data = if let Some(user_offset) = self.offset.checked_sub(system_len) {
            self.user_attrs.get(user_offset..)?
        } else {
            self.system_attrs.get(self.offset..)?
        };
        let (&size, names) = data.split_first()?;
        let name = names.get(..usize::from(size))?;
        self.offset = self.offset.checked_add(usize::from(size))?.checked_add(1)?;
        let namespace = if self.offset < system_len {
            EXTATTR_NAMESPACE_SYSTEM_STRING
        } else {
            EXTATTR_NAMESPACE_USER_STRING
        };
        Some(prefix_namespace(OsStr::from_bytes(name), namespace))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.offset.checked_sub(self.system_attrs.len()) == Some(self.user_attrs.len()) {
            (0, Some(0))
        } else {
            (1, None)
        }
    }
}

fn name_to_ns(name: &OsStr) -> io::Result<(c_int, CString)> {
    let mut groups = name.as_bytes().splitn(2, |&b| b == b'.').take(2);
    let Some(nsname) = groups.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "couldn't find namespace",
        ));
    };

    let Some(propname) = groups.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "couldn't find attribute",
        ));
    };

    let Some(ns_int) = EXTATTR_NAMESPACE_NAMES
        .iter()
        .position(|&s| s.as_bytes() == nsname)
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no matching namespace",
        ));
    };

    Ok((
        c_int::try_from(ns_int).map_err(io::Error::other)?,
        CString::new(propname)?,
    ))
}

fn prefix_namespace(attr: &OsStr, nsname: &str) -> OsString {
    let mut v = nsname.as_bytes().to_vec();
    v.push(b'.');
    v.extend(attr.as_bytes());
    OsString::from_vec(v)
}

pub(crate) fn get_fd(fd: RawFd, name: &OsStr) -> io::Result<Vec<u8>> {
    let (ns, name) = name_to_ns(name)?;
    let read = |buf: *mut u8, len| {
        // SAFETY: allocate_loop supplies a writable buffer of len bytes or a null size probe. The name is a live C string.
        unsafe { extattr_get_fd(fd, ns, name.as_ptr(), buf.cast::<c_void>(), len) }
    };
    // SAFETY: On buffered success, the OS initializes exactly the returned byte count.
    unsafe { allocate_loop(read) }
}

pub(crate) fn set_fd(fd: RawFd, name: &OsStr, value: &[u8]) -> io::Result<()> {
    let (ns, name) = name_to_ns(name)?;
    // SAFETY: The name is a live C string. The value slice is readable for its stated length.
    let ret = unsafe {
        extattr_set_fd(
            fd,
            ns,
            name.as_ptr(),
            value.as_ptr().cast::<c_void>(),
            value.len(),
        )
    };
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn remove_fd(fd: RawFd, name: &OsStr) -> io::Result<()> {
    let (ns, name) = name_to_ns(name)?;
    // SAFETY: The name is a live C string.
    let ret = unsafe { extattr_delete_fd(fd, ns, name.as_ptr()) };
    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn list_fd(fd: RawFd) -> io::Result<XAttrs> {
    let read = |buf: *mut u8, len| {
        // SAFETY: allocate_loop supplies a writable buffer of len bytes or a null size probe.
        unsafe {
            extattr_list_fd(
                fd,
                EXTATTR_NAMESPACE_SYSTEM,
                buf.cast::<c_void>(),
                len,
            )
        }
    };
    // SAFETY: On buffered success, the OS initializes exactly the returned byte count.
    let res = unsafe { allocate_loop(read) };
    // FreeBSD requires root to list system attributes. Treat EPERM as an empty
    // system namespace so callers can still list user attributes.
    let sysvec = match res {
        Ok(v) => v,
        Err(err) => {
            if err.raw_os_error() == Some(EPERM) {
                Vec::new()
            } else {
                return Err(err);
            }
        }
    };

    let read = |buf: *mut u8, len| {
        // SAFETY: allocate_loop supplies a writable buffer of len bytes or a null size probe.
        unsafe {
            extattr_list_fd(
                fd,
                EXTATTR_NAMESPACE_USER,
                buf.cast::<c_void>(),
                len,
            )
        }
    };
    // SAFETY: On buffered success, the OS initializes exactly the returned byte count.
    let uservec = unsafe { allocate_loop(read) }?;

    validate_list(&sysvec)?;
    validate_list(&uservec)?;
    Ok(XAttrs {
        system_attrs: sysvec.into_boxed_slice(),
        user_attrs: uservec.into_boxed_slice(),
        offset: 0,
    })
}

pub(crate) fn get_path(path: &Path, name: &OsStr) -> io::Result<Vec<u8>> {
    let (ns, name) = name_to_ns(name)?;
    let path = path_to_c(path)?;
    let read = |buf: *mut u8, len| {
        // SAFETY: allocate_loop supplies a writable buffer of len bytes or a null size probe. The path and name are live C strings.
        unsafe {
            extattr_get_link(
                path.as_ptr(),
                ns,
                name.as_ptr(),
                buf.cast::<c_void>(),
                len,
            )
        }
    };
    // SAFETY: On buffered success, the OS initializes exactly the returned byte count.
    unsafe { allocate_loop(read) }
}

pub(crate) fn set_path(path: &Path, name: &OsStr, value: &[u8]) -> io::Result<()> {
    let (ns, name) = name_to_ns(name)?;
    let path = path_to_c(path)?;
    // SAFETY: The path and name are live C strings. The value slice is readable for its stated length.
    let ret = unsafe {
        extattr_set_link(
            path.as_ptr(),
            ns,
            name.as_ptr(),
            value.as_ptr().cast::<c_void>(),
            value.len(),
        )
    };
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn remove_path(path: &Path, name: &OsStr) -> io::Result<()> {
    let (ns, name) = name_to_ns(name)?;
    let path = path_to_c(path)?;
    // SAFETY: The path and name are live C strings.
    let ret = unsafe { extattr_delete_link(path.as_ptr(), ns, name.as_ptr()) };
    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn list_path(path: &Path) -> io::Result<XAttrs> {
    let path = path_to_c(path)?;
    let read = |buf: *mut u8, len| {
        // SAFETY: allocate_loop supplies a writable buffer of len bytes or a null size probe. The path is a live C string.
        unsafe {
            extattr_list_link(
                path.as_ptr(),
                EXTATTR_NAMESPACE_SYSTEM,
                buf.cast::<c_void>(),
                len,
            )
        }
    };
    // SAFETY: On buffered success, the OS initializes exactly the returned byte count.
    let res = unsafe { allocate_loop(read) };
    // FreeBSD requires root to list system attributes. Treat EPERM as an empty
    // system namespace so callers can still list user attributes.
    let sysvec = match res {
        Ok(v) => v,
        Err(err) => {
            if err.raw_os_error() == Some(EPERM) {
                Vec::new()
            } else {
                return Err(err);
            }
        }
    };

    let read = |buf: *mut u8, len| {
        // SAFETY: allocate_loop supplies a writable buffer of len bytes or a null size probe. The path is a live C string.
        unsafe {
            extattr_list_link(
                path.as_ptr(),
                EXTATTR_NAMESPACE_USER,
                buf.cast::<c_void>(),
                len,
            )
        }
    };
    // SAFETY: On buffered success, the OS initializes exactly the returned byte count.
    let uservec = unsafe { allocate_loop(read) }?;

    validate_list(&sysvec)?;
    validate_list(&uservec)?;
    Ok(XAttrs {
        system_attrs: sysvec.into_boxed_slice(),
        user_attrs: uservec.into_boxed_slice(),
        offset: 0,
    })
}

fn validate_list(mut data: &[u8]) -> io::Result<()> {
    while let Some((&size, names)) = data.split_first() {
        data = names
            .get(usize::from(size)..)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Truncated xattr name"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_truncated_length_prefixed_name() {
        let error = validate_list(b"\x03abc\x04de").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        validate_list(b"\x03abc\x02de").unwrap();
    }
}
