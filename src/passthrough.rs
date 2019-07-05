// PassthroughFS :: A filesystem that passes all calls through to another underlying filesystem.
//
// Implemented using fuse_mt::FilesystemMT.
//
// Copyright (c) 2016-2019 by William R. Fraser
//

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::path::{Path, PathBuf};

use super::libc_extras::libc;
use super::libc_wrappers;

extern crate regex;

use fuse_mt::*;
use time::*;

pub struct PassthroughFS {
    pub target: OsString,
    map_regex: regex::Regex,
    mapped_regex: regex::Regex,
}

fn mode_to_filetype(mode: libc::mode_t) -> FileType {
    match mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFREG => FileType::RegularFile,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFBLK => FileType::BlockDevice,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFSOCK => FileType::Socket,
        _ => {
            panic!("unknown file type");
        }
    }
}

fn stat_to_fuse(stat: libc::stat64) -> FileAttr {
    // st_mode encodes both the kind and the permissions
    let kind = mode_to_filetype(stat.st_mode);
    let perm = (stat.st_mode & 0o7777) as u16;

    FileAttr {
        size: stat.st_size as u64,
        blocks: stat.st_blocks as u64,
        atime: Timespec {
            sec: stat.st_atime as i64,
            nsec: stat.st_atime_nsec as i32,
        },
        mtime: Timespec {
            sec: stat.st_mtime as i64,
            nsec: stat.st_mtime_nsec as i32,
        },
        ctime: Timespec {
            sec: stat.st_ctime as i64,
            nsec: stat.st_ctime_nsec as i32,
        },
        crtime: Timespec { sec: 0, nsec: 0 },
        kind,
        perm,
        nlink: stat.st_nlink as u32,
        uid: stat.st_uid,
        gid: stat.st_gid,
        rdev: stat.st_rdev as u32,
        flags: 0,
    }
}

#[cfg(target_os = "macos")]
fn statfs_to_fuse(statfs: libc::statfs) -> Statfs {
    Statfs {
        blocks: statfs.f_blocks,
        bfree: statfs.f_bfree,
        bavail: statfs.f_bavail,
        files: statfs.f_files,
        ffree: statfs.f_ffree,
        bsize: statfs.f_bsize as u32,
        namelen: 0, // TODO
        frsize: 0,  // TODO
    }
}

#[cfg(target_os = "linux")]
fn statfs_to_fuse(statfs: libc::statfs) -> Statfs {
    Statfs {
        blocks: statfs.f_blocks as u64,
        bfree: statfs.f_bfree as u64,
        bavail: statfs.f_bavail as u64,
        files: statfs.f_files as u64,
        ffree: statfs.f_ffree as u64,
        bsize: statfs.f_bsize as u32,
        namelen: statfs.f_namelen as u32,
        frsize: statfs.f_frsize as u32,
    }
}

impl PassthroughFS {
    pub fn new(root: OsString) -> PassthroughFS {
        PassthroughFS {
            target: root,
            mapped_regex: regex::Regex::new("\\.mapped\\.(cb[r|z])$").unwrap(),
            map_regex: regex::Regex::new("\\.(zip|rar)$").unwrap(),
        }
    }

    fn map_name(&self, name: &OsString) -> OsString {
        match name.to_str() {
            None => {
                return name.to_owned();
            }
            Some(utf8) => match self.map_regex.captures(utf8) {
                None => {
                    return name.to_owned();
                }
                Some(matches) => match matches[1].as_ref() {
                    "rar" => {
                        let replaced = self.map_regex.replace(&utf8, ".mapped.cbr").into_owned();
                        OsString::from(replaced)
                    }
                    "zip" => {
                        let replaced = self.map_regex.replace(&utf8, ".mapped.cbz").into_owned();
                        OsString::from(replaced)
                    }
                    _ => {
                        panic!();
                    }
                },
            },
        }
    }

    fn real_path(&self, partial: &Path) -> OsString {
        let mut used = PathBuf::new();

        let convert = partial.to_str();

        match convert {
            None => {}
            Some(utf8) => match self.mapped_regex.captures(utf8) {
                Some(v) => match v[1].as_ref() {
                    "cbz" => {
                        used = PathBuf::from(self.mapped_regex.replace(utf8, ".zip").into_owned());
                    }
                    "cbr" => {
                        used = PathBuf::from(self.mapped_regex.replace(utf8, ".rar").into_owned());
                    }
                    _ => {
                        used = partial.to_owned();
                    }
                },
                None => {
                    used = partial.to_owned();
                }
            },
        }

        debug!(" used: {:?}", used);

        let ret = PathBuf::from(&self.target)
            .join(used.strip_prefix("/").unwrap())
            .into_os_string();

        debug!("ret {:?}", ret);

        ret
    }

    fn stat_real(&self, path: &Path) -> io::Result<FileAttr> {
        let real: OsString = self.real_path(path);
        debug!("stat_real: {:?}", real);

        match libc_wrappers::lstat(real) {
            Ok(stat) => Ok(stat_to_fuse(stat)),
            Err(e) => {
                let err = io::Error::from_raw_os_error(e);
                error!("lstat({:?}): {}", path, err);
                Err(err)
            }
        }
    }
}

const TTL: Timespec = Timespec { sec: 1, nsec: 0 };

impl FilesystemMT for PassthroughFS {
    fn init(&self, _req: RequestInfo) -> ResultEmpty {
        debug!("init");
        Ok(())
    }

    fn destroy(&self, _req: RequestInfo) {
        debug!("destroy");
    }

    fn getattr(&self, _req: RequestInfo, path: &Path, fh: Option<u64>) -> ResultEntry {
        debug!("getattr: {:?}", path);

        if let Some(fh) = fh {
            match libc_wrappers::fstat(fh) {
                Ok(stat) => Ok((TTL, stat_to_fuse(stat))),
                Err(e) => Err(e),
            }
        } else {
            match self.stat_real(path) {
                Ok(attr) => Ok((TTL, attr)),
                Err(e) => Err(e.raw_os_error().unwrap()),
            }
        }
    }

    fn opendir(&self, _req: RequestInfo, path: &Path, _flags: u32) -> ResultOpen {
        let real = self.real_path(path);
        debug!("opendir: {:?} (flags = {:#o})", real, _flags);
        match libc_wrappers::opendir(real) {
            Ok(fh) => Ok((fh, 0)),
            Err(e) => {
                let ioerr = io::Error::from_raw_os_error(e);
                error!("opendir({:?}): {}", path, ioerr);
                Err(e)
            }
        }
    }

    fn releasedir(&self, _req: RequestInfo, path: &Path, fh: u64, _flags: u32) -> ResultEmpty {
        debug!("releasedir: {:?}", path);
        libc_wrappers::closedir(fh)
    }

    fn readdir(&self, _req: RequestInfo, path: &Path, fh: u64) -> ResultReaddir {
        debug!("readdir: {:?}", path);
        let mut entries: Vec<DirectoryEntry> = vec![];

        if fh == 0 {
            error!("readdir: missing fh");
            return Err(libc::EINVAL);
        }

        loop {
            match libc_wrappers::readdir(fh) {
                Ok(Some(entry)) => {
                    let name_c = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) };
                    let name = OsStr::from_bytes(name_c.to_bytes()).to_owned();

                    let filetype = match entry.d_type {
                        libc::DT_DIR => FileType::Directory,
                        libc::DT_REG => FileType::RegularFile,
                        libc::DT_LNK => FileType::Symlink,
                        libc::DT_BLK => FileType::BlockDevice,
                        libc::DT_CHR => FileType::CharDevice,
                        libc::DT_FIFO => FileType::NamedPipe,
                        libc::DT_SOCK => {
                            warn!("FUSE doesn't support Socket file type; translating to NamedPipe instead.");
                            FileType::NamedPipe
                        }
                        0 | _ => {
                            let entry_path = PathBuf::from(path).join(&name);
                            let real_path = self.real_path(&entry_path);
                            match libc_wrappers::lstat(real_path) {
                                Ok(stat64) => mode_to_filetype(stat64.st_mode),
                                Err(errno) => {
                                    let ioerr = io::Error::from_raw_os_error(errno);
                                    panic!("lstat failed after readdir_r gave no file type for {:?}: {}",
                                           entry_path, ioerr);
                                }
                            }
                        }
                    };

                    entries.push(DirectoryEntry {
                        name: self.map_name(&name),
                        kind: filetype,
                    })
                }
                Ok(None) => {
                    break;
                }
                Err(e) => {
                    error!("readdir: {:?}: {}", path, e);
                    return Err(e);
                }
            }
        }

        Ok(entries)
    }

    fn open(&self, _req: RequestInfo, path: &Path, flags: u32) -> ResultOpen {
        debug!("open: {:?} flags={:#x}", path, flags);

        let real = self.real_path(path);
        match libc_wrappers::open(real, flags as libc::c_int) {
            Ok(fh) => Ok((fh, flags)),
            Err(e) => {
                error!("open({:?}): {}", path, io::Error::from_raw_os_error(e));
                Err(e)
            }
        }
    }

    fn release(
        &self,
        _req: RequestInfo,
        path: &Path,
        fh: u64,
        _flags: u32,
        _lock_owner: u64,
        _flush: bool,
    ) -> ResultEmpty {
        debug!("release: {:?}", path);
        libc_wrappers::close(fh)
    }

    fn read(
        &self,
        _req: RequestInfo,
        path: &Path,
        fh: u64,
        offset: u64,
        size: u32,
        result: impl FnOnce(Result<&[u8], libc::c_int>),
    ) {
        debug!("read: {:?} {:#x} @ {:#x}", path, size, offset);
        let mut file = unsafe { UnmanagedFile::new(fh) };

        let mut data = Vec::<u8>::with_capacity(size as usize);
        unsafe { data.set_len(size as usize) };

        if let Err(e) = file.seek(SeekFrom::Start(offset)) {
            error!("seek({:?}, {}): {}", path, offset, e);
            result(Err(e.raw_os_error().unwrap()));
            return;
        }
        match file.read(&mut data) {
            Ok(n) => {
                data.truncate(n);
            }
            Err(e) => {
                error!("read {:?}, {:#x} @ {:#x}: {}", path, size, offset, e);
                result(Err(e.raw_os_error().unwrap()));
                return;
            }
        }

        result(Ok(&data));
    }

    fn readlink(&self, _req: RequestInfo, path: &Path) -> ResultData {
        debug!("readlink: {:?}", path);

        let real = self.real_path(path);
        match ::std::fs::read_link(real) {
            Ok(target) => Ok(target.into_os_string().into_vec()),
            Err(e) => Err(e.raw_os_error().unwrap()),
        }
    }

    fn statfs(&self, _req: RequestInfo, path: &Path) -> ResultStatfs {
        debug!("statfs: {:?}", path);

        let real = self.real_path(path);
        let mut buf: libc::statfs = unsafe { ::std::mem::zeroed() };
        let result = unsafe {
            let path_c = CString::from_vec_unchecked(real.into_vec());
            libc::statfs(path_c.as_ptr(), &mut buf)
        };

        if -1 == result {
            let e = io::Error::last_os_error();
            error!("statfs({:?}): {}", path, e);
            Err(e.raw_os_error().unwrap())
        } else {
            Ok(statfs_to_fuse(buf))
        }
    }
}

/// A file that is not closed upon leaving scope.
struct UnmanagedFile {
    inner: Option<File>,
}

impl UnmanagedFile {
    unsafe fn new(fd: u64) -> UnmanagedFile {
        UnmanagedFile {
            inner: Some(File::from_raw_fd(fd as i32)),
        }
    }
}

impl Drop for UnmanagedFile {
    fn drop(&mut self) {
        // Release control of the file descriptor so it is not closed.
        let file = self.inner.take().unwrap();
        file.into_raw_fd();
    }
}

impl Read for UnmanagedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.as_ref().unwrap().read(buf)
    }
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.inner.as_ref().unwrap().read_to_end(buf)
    }
}

impl Seek for UnmanagedFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.as_ref().unwrap().seek(pos)
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_add() {
        let fs = PassthroughFS::new(OsString::from("abc"));

        assert_eq!(fs.real_path(Path::new("/bbc")), "abc/bbc");

        let reg = regex::Regex::new("\\.mapped\\.(cb[r|z])").unwrap();
        assert!(reg.is_match("a.mapped.cbz"));

        assert_eq!(reg.captures("a.mapped.cbz").unwrap()[1], "cbz".to_owned());

        assert_eq!(
            Path::new(
                Path::new(PathBuf::from("a.mapped.cbz").file_stem().unwrap())
                    .file_stem()
                    .unwrap()
            )
            .with_extension("zip"),
            OsString::from("a.zip")
        );

        assert_eq!(fs.real_path(Path::new("/bbc.mapped.cbz")), "abc/bbc.zip");
        assert_eq!(fs.real_path(Path::new("/sbc.mapped.cbr")), "abc/sbc.rar");
        assert_eq!(fs.real_path(Path::new("/bbc.maed.cbz")), "abc/bbc.maed.cbz");
        assert_eq!(
            fs.real_path(Path::new("/bbc.maped.cbr")),
            "abc/bbc.maped.cbr"
        );
        assert_eq!(
            fs.real_path(Path::new("/a.mapped.mapped.cbz")),
            "abc/a.mapped.zip"
        );

        assert_eq!(fs.map_name(&OsString::from("a.zip")), "a.mapped.cbz");
        assert_eq!(fs.map_name(&OsString::from("a.b.rar")), "a.b.mapped.cbr");
        assert_eq!(fs.map_name(&OsString::from("a.b.cbz")), "a.b.cbz");
        assert_eq!(fs.map_name(&OsString::from("ab.cbz")), "ab.cbz");
    }

}
