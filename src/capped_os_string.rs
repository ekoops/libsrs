use crate::buffer_writer::{BufferWriter, FromBufferWriter};
use std::cmp;
use std::ffi::{OsStr, OsString};
use std::io;
use std::ops::Deref;
use std::os::unix::ffi::OsStringExt;

/// An [OsString] with a maximum length equal to `MAX_LEN`.
#[derive(Debug, Clone, Default)]
pub struct CappedOsString<const MAX_LEN: usize>(OsString);

/// Error returned by [CappedOsString::new].
#[derive(Debug, Clone, thiserror::Error)]
#[error("string length {actual_len} exceeds maximum {max_len}")]
pub struct OsStringTooLongError {
    actual_len: usize,
    max_len: usize,
}

impl<const MAX_LEN: usize> CappedOsString<MAX_LEN> {
    /// Creates a new [CappedOsString] from any [AsRef<OsStr>].
    pub fn new<T: AsRef<OsStr>>(s: T) -> Result<Self, OsStringTooLongError> {
        let s = s.as_ref();
        let len = s.len();
        if len > MAX_LEN {
            return Err(OsStringTooLongError { actual_len: len, max_len: MAX_LEN});
        }
        Ok(Self(OsString::from(s)))
    }
}

impl<const MAX_LEN: usize> FromBufferWriter<u8> for CappedOsString<MAX_LEN> {
    #[inline]
    fn from_buffer_writer<W: BufferWriter<u8>>(writer: W) -> io::Result<Self> {
        let mut buff = [0u8; MAX_LEN];
        let written_bytes = writer.write(&mut buff)?;
        // Cap written bytes to be sure it is not bigger than buffer size.
        let written_bytes = cmp::min(written_bytes, buff.len());
        let vec = buff[..written_bytes].to_vec();
        Ok(Self(OsString::from_vec(vec)))
    }
}

impl<const MAX_LEN: usize> Deref for CappedOsString<MAX_LEN> {
    type Target = OsString;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
