use libc::c_char;
use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::io::Read;

/// Fill `buff` with data read from `file`. Returns the amount `n` of bytes read from `file`, such
/// that `0` <= `n` <= `buff.len()`. `n` < `buff.len()` only if the end-of-file is reached before
/// filling the buffer, or an unrecoverable error (any error of kind other than
/// [io::ErrorKind::Interrupted]) is encountered. Any interruption (error of kind
/// [io::ErrorKind::Interrupted]) is handled by continuing the reading from `file`.
pub fn read_exact(file: &mut File, buff: &mut [u8]) -> io::Result<usize> {
    let mut read_bytes = 0;
    while read_bytes < buff.len() {
        match file.read(&mut buff[read_bytes..]) {
            Ok(0) => break,
            Ok(n) => read_bytes += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(read_bytes)
}

/// Read the content of the symbolic link `path` into `buff`. Return the amount of data read.
pub fn readlink(path: &CStr, buff: &mut [u8]) -> io::Result<usize> {
    let ret = unsafe {
        libc::readlink(
            path.as_ptr() as *const c_char,
            buff.as_ptr() as *mut c_char,
            buff.len(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(ret as usize)
}
