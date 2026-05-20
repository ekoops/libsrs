use std::{io, mem};

/// Updates `*buff` to point to `n`-th element from the current position.
fn advance_buff<T>(buff: &mut &mut [T], n: usize) {
    let (_, new_buff) = mem::take(buff).split_at_mut(n);
    *buff = new_buff;
}

/// An abstraction for types that can write elements of type `[T]` into a provided mutable buffer.
pub trait BufferWriter<T> {
    /// Writes data into `buff` and returns the number of elements written.
    fn write_to_buff(self, buff: &mut [T]) -> io::Result<usize>;

    /// Writes data into `buff` and returns the number of elements written.  Updates `*buff` to
    /// point to the first unwritten element.
    fn write_next_to_buff(self, buff: &mut &mut [T]) -> io::Result<usize>
    where
        Self: Sized,
    {
        let written_elems = self.write_to_buff(buff)?;
        advance_buff(buff, written_elems);
        Ok(written_elems)
    }
}

/// Blanket implementation allowing the use of closures as [BufferWriter].
impl<T, F> BufferWriter<T> for F
where
    F: FnOnce(&mut [T]) -> io::Result<usize>,
{
    fn write_to_buff(self, buff: &mut [T]) -> io::Result<usize> {
        self(buff)
    }
}

/// A trait for types that can be constructed by providing a scratch buffer of elements of type
/// `[T]` to a writer.
pub trait FromBufferWriter<T>: Sized {
    /// Constructs an instance of [Self] by leveraging `writer`.
    fn from_buffer_writer<W: BufferWriter<T>>(writer: W) -> io::Result<Self>;
}
