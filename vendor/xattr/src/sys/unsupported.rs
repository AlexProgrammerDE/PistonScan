use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::io::RawFd;
use std::path::Path;

use UnsupportedPlatformError;

/// An iterator over a set of extended attributes names.
#[derive(Clone, Debug)]
pub struct XAttrs;

impl Iterator for XAttrs {
    type Item = OsString;
    fn next(&mut self) -> Option<OsString> {
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(0))
    }
}

pub(crate) fn get_fd(_: RawFd, _: &OsStr) -> io::Result<Vec<u8>> {
    Err(io::Error::other(UnsupportedPlatformError))
}

pub(crate) fn set_fd(_: RawFd, _: &OsStr, _: &[u8]) -> io::Result<()> {
    Err(io::Error::other(UnsupportedPlatformError))
}

pub(crate) fn remove_fd(_: RawFd, _: &OsStr) -> io::Result<()> {
    Err(io::Error::other(UnsupportedPlatformError))
}

pub(crate) fn list_fd(_: RawFd) -> io::Result<XAttrs> {
    Err(io::Error::other(UnsupportedPlatformError))
}

pub(crate) fn get_path(_: &Path, _: &OsStr) -> io::Result<Vec<u8>> {
    Err(io::Error::other(UnsupportedPlatformError))
}

pub(crate) fn set_path(_: &Path, _: &OsStr, _: &[u8]) -> io::Result<()> {
    Err(io::Error::other(UnsupportedPlatformError))
}

pub(crate) fn remove_path(_: &Path, _: &OsStr) -> io::Result<()> {
    Err(io::Error::other(UnsupportedPlatformError))
}

pub(crate) fn list_path(_: &Path) -> io::Result<XAttrs> {
    Err(io::Error::other(UnsupportedPlatformError))
}
