#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

#[cfg(any(target_os = "linux", target_os = "android"))]
use self::linux::{fgetxattr, flistxattr, fremovexattr, fsetxattr, lgetxattr, llistxattr, lremovexattr, lsetxattr};

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
use self::macos::{fgetxattr, flistxattr, fremovexattr, fsetxattr, lgetxattr, llistxattr, lremovexattr, lsetxattr};

use std::ffi::{OsStr, OsString};
use std::io;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::Path;

use libc::{c_char, c_void};

use util::{allocate_loop, name_to_c, path_to_c};

/// An iterator over a set of extended attributes names.
#[derive(Debug)]
pub struct XAttrs {
    data: Box<[u8]>,
    offset: usize,
}

impl Clone for XAttrs {
    fn clone(&self) -> Self {
        Self {
            data: Vec::from(&*self.data).into_boxed_slice(),
            offset: self.offset,
        }
    }
    fn clone_from(&mut self, other: &Self) {
        self.offset = other.offset;

        let mut data = mem::replace(&mut self.data, Box::new([])).into_vec();
        data.extend(other.data.iter().copied());
        self.data = data.into_boxed_slice();
    }
}

// Yes, I could avoid these allocations on linux/macos. However, if we ever want to be freebsd
// compatible, we need to be able to prepend the namespace to the extended attribute names.
// Furthermore, borrowing makes the API messy.
impl Iterator for XAttrs {
    type Item = OsString;
    fn next(&mut self) -> Option<OsString> {
        let data = self.data.get(self.offset..)?;
        let end = data.iter().position(|&byte| byte == 0)?;
        let name = data.get(..end)?;
        self.offset = self.offset.checked_add(end)?.checked_add(1)?;
        Some(OsStr::from_bytes(name).to_owned())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.data.len() == self.offset {
            (0, Some(0))
        } else {
            (1, None)
        }
    }
}

pub(crate) fn get_fd(fd: RawFd, name: &OsStr) -> io::Result<Vec<u8>> {
    let name = name_to_c(name)?;
    let read = |buf: *mut u8, len| {
        // SAFETY: allocate_loop supplies a writable buffer of len bytes or a null size probe. The name is a live C string.
        unsafe { fgetxattr(fd, name.as_ptr(), buf.cast::<c_void>(), len) }
    };
    // SAFETY: On buffered success, the OS initializes exactly the returned byte count.
    unsafe { allocate_loop(read) }
}

pub(crate) fn set_fd(fd: RawFd, name: &OsStr, value: &[u8]) -> io::Result<()> {
    let name = name_to_c(name)?;
    // SAFETY: The name is a live C string. The value slice is readable for its stated length.
    let ret = unsafe {
        fsetxattr(
            fd,
            name.as_ptr(),
            value.as_ptr().cast::<c_void>(),
            value.len(),
        )
    };
    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn remove_fd(fd: RawFd, name: &OsStr) -> io::Result<()> {
    let name = name_to_c(name)?;
    // SAFETY: The name is a live C string.
    let ret = unsafe { fremovexattr(fd, name.as_ptr()) };
    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn list_fd(fd: RawFd) -> io::Result<XAttrs> {
    let read = |buf: *mut u8, len| {
        // SAFETY: allocate_loop supplies a writable buffer of len bytes or a null size probe.
        unsafe { flistxattr(fd, buf.cast::<c_char>(), len) }
    };
    // SAFETY: On buffered success, the OS initializes exactly the returned byte count.
    let vec = unsafe { allocate_loop(read) }?;
    parse_list(vec)
}

pub(crate) fn get_path(path: &Path, name: &OsStr) -> io::Result<Vec<u8>> {
    let name = name_to_c(name)?;
    let path = path_to_c(path)?;
    let read = |buf: *mut u8, len| {
        // SAFETY: allocate_loop supplies a writable buffer of len bytes or a null size probe. The path and name are live C strings.
        unsafe { lgetxattr(
                path.as_ptr(),
                name.as_ptr(),
                buf.cast::<c_void>(),
                len,
            ) }
    };
    // SAFETY: On buffered success, the OS initializes exactly the returned byte count.
    unsafe { allocate_loop(read) }
}

pub(crate) fn set_path(path: &Path, name: &OsStr, value: &[u8]) -> io::Result<()> {
    let name = name_to_c(name)?;
    let path = path_to_c(path)?;
    // SAFETY: The path and name are live C strings. The value slice is readable for its stated length.
    let ret = unsafe {
        lsetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast::<c_void>(),
            value.len(),
        )
    };
    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn remove_path(path: &Path, name: &OsStr) -> io::Result<()> {
    let name = name_to_c(name)?;
    let path = path_to_c(path)?;
    // SAFETY: The path and name are live C strings.
    let ret = unsafe { lremovexattr(path.as_ptr(), name.as_ptr()) };
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
        unsafe { llistxattr(path.as_ptr(), buf.cast::<c_char>(), len) }
    };
    // SAFETY: On buffered success, the OS initializes exactly the returned byte count.
    let vec = unsafe { allocate_loop(read) }?;
    parse_list(vec)
}

fn parse_list(data: Vec<u8>) -> io::Result<XAttrs> {
    if data.last().is_some_and(|&last| last != 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unterminated xattr name",
        ));
    }
    Ok(XAttrs {
        data: data.into_boxed_slice(),
        offset: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unterminated_names() {
        let result = parse_list(b"user.good\0user.truncated".to_vec());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn reads_null_terminated_names() {
        let names = parse_list(b"user.first\0user.second\0".to_vec()).unwrap();
        assert!(names.eq(["user.first", "user.second"].iter().map(OsString::from)));
    }
}
