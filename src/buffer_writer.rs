use std::io;

/// An abstraction for types that can write data into a provided mutable buffer.
pub trait BufferWriter {
    /// Write data into `buff` and return the number of bytes written.
    fn write(self, buff: &mut [u8]) -> io::Result<usize>;
}

/// Blanket implementation allowing the use of closures as [BufferWriter].
impl<F> BufferWriter for F
where
    F: FnOnce(&mut [u8]) -> io::Result<usize>,
{
    fn write(self, buff: &mut [u8]) -> io::Result<usize> {
        self(buff)
    }
}

/// A trait for types that can be constructed by providing a scratch buffer to a writer.
pub trait FromBufferWriter: Sized {
    /// Construct an instance of [Self] by leveraging `writer`.
    fn from_buffer_writer<W: BufferWriter>(writer: W) -> io::Result<Self>;
}
