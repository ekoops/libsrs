use crate::buffer_writer::{BufferWriter, FromBufferWriter};
use std::cmp;
use std::ffi::OsString;
use std::io;
use std::ops::Deref;
use std::os::unix::ffi::OsStringExt;

/// An [OsString] with a maximum length equal to [MAX_LEN].
#[derive(Clone, Default)]
pub struct CappedOsString<const MAX_LEN: usize>(OsString);

impl<const MAX_LEN: usize> FromBufferWriter<u8> for CappedOsString<MAX_LEN> {
    #[inline]
    fn from_buffer_writer<W: BufferWriter<u8>>(writer: W) -> io::Result<Self> {
        let mut buff = vec![0u8; MAX_LEN];
        let written_bytes = writer.write(&mut buff)?;
        // Cap written bytes to be sure it is not bigger than buffer size.
        let written_bytes = cmp::min(written_bytes, buff.len());
        buff.truncate(written_bytes);
        Ok(Self(OsString::from_vec(buff)))
    }
}

impl<const MAX_LEN: usize> Deref for CappedOsString<MAX_LEN> {
    type Target = OsString;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
