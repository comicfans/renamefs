// Libc Wrappers :: Safe wrappers around system calls.
//
// Copyright (c) 2016-2019 by William R. Fraser
//

use libc_extras::libc;
use std::ffi::{CString, OsString};
use std::io;
use std::mem;
use std::os::unix::ffi::OsStringExt;
use std::ptr;

macro_rules! into_cstring {
    ($path:expr, $syscall:expr) => {
        match CString::new($path.into_vec()) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    concat!($syscall, ": path {:?} contains interior NUL byte"),
                    OsString::from_vec(e.into_vec())
                );
                return Err(libc::EINVAL);
            }
        }
    };
}

pub fn opendir(path: OsString) -> Result<u64, libc::c_int> {
    let path_c = into_cstring!(path, "opendir");

    let dir: *mut libc::DIR = unsafe { libc::opendir(path_c.as_ptr()) };
    if dir.is_null() {
        return Err(io::Error::last_os_error().raw_os_error().unwrap());
    }

    Ok(dir as u64)
}

pub fn readdir(fh: u64) -> Result<Option<libc::dirent>, libc::c_int> {
    let dir = fh as usize as *mut libc::DIR;
    let mut entry: libc::dirent = unsafe { mem::zeroed() };
    let mut result: *mut libc::dirent = ptr::null_mut();

    let error: i32 = unsafe { libc::readdir_r(dir, &mut entry, &mut result) };
    if error != 0 {
        return Err(error);
    }

    if result.is_null() {
        return Ok(None);
    }

    Ok(Some(entry))
}

pub fn closedir(fh: u64) -> Result<(), libc::c_int> {
    let dir = fh as usize as *mut libc::DIR;
    if -1 == unsafe { libc::closedir(dir) } {
        Err(io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        Ok(())
    }
}

pub fn open(path: OsString, flags: libc::c_int) -> Result<u64, libc::c_int> {
    let path_c = into_cstring!(path, "open");

    let fd: libc::c_int = unsafe { libc::open(path_c.as_ptr(), flags) };
    if fd == -1 {
        return Err(io::Error::last_os_error().raw_os_error().unwrap());
    }

    Ok(fd as u64)
}

pub fn close(fh: u64) -> Result<(), libc::c_int> {
    let fd = fh as libc::c_int;
    if -1 == unsafe { libc::close(fd) } {
        Err(io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        Ok(())
    }
}

pub fn lstat(path: OsString) -> Result<libc::stat64, libc::c_int> {
    let path_c = into_cstring!(path, "lstat");

    let mut buf: libc::stat64 = unsafe { mem::zeroed() };
    if -1 == unsafe { libc::lstat64(path_c.as_ptr(), &mut buf) } {
        return Err(io::Error::last_os_error().raw_os_error().unwrap());
    }

    Ok(buf)
}

pub fn fstat(fd: u64) -> Result<libc::stat64, libc::c_int> {
    let mut buf: libc::stat64 = unsafe { mem::zeroed() };
    if -1 == unsafe { libc::fstat64(fd as libc::c_int, &mut buf) } {
        return Err(io::Error::last_os_error().raw_os_error().unwrap());
    }

    Ok(buf)
}




