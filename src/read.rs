use rustix::fs::{self, CWD};
use std::ffi::CStr;
use std::io::{self, Read};
use std::ops::ControlFlow;

/// Fill `buff` with data read from `reader`. Returns the amount `n` of bytes read from `reader`,
/// such that `0` <= `n` <= `buff.len()`. `n` < `buff.len()` only if the end-of-file is reached
/// before filling the buffer, or an unrecoverable error (any error of kind other than
/// [io::ErrorKind::Interrupted]) is encountered. Any interruption (error of kind
/// [io::ErrorKind::Interrupted]) is handled by continuing the reading from `reader`.
pub fn exact<R: Read>(reader: &mut R, buff: &mut [u8]) -> io::Result<usize> {
    let mut read_bytes = 0;
    while read_bytes < buff.len() {
        match reader.read(&mut buff[read_bytes..]) {
            Ok(0) => break,
            Ok(n) => read_bytes += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(read_bytes)
}

/// An abstraction for types that can process lines of data.
pub trait LineProcessor {
    /// Processes a line of data.
    ///
    /// The returned value can be used to control the flow of execution.
    fn process(&mut self, line: &[u8]) -> io::Result<ControlFlow<()>>;
}

/// Blanket implementation allowing the use of closures as [LineProcessor].
impl<F> LineProcessor for F
where
    F: FnMut(&[u8]) -> io::Result<ControlFlow<()>>,
{
    fn process(&mut self, line: &[u8]) -> io::Result<ControlFlow<()>> {
        self(line)
    }
}

/// Reads lines from `reader` and passes them to `line_processor`, using `buff` as a scratch buffer.
///
/// This function reads data until End-of-File (EOF) or until `line_processor` requests early
/// termination. Each complete line (delimited by `\n`) is passed to `line_processor` with the
/// trailing newline character removed.
///
/// # Behavior
///
/// * **Buffer Limit:** The length of `buff` determines the maximum allowed line length.
/// * **Interruption:** Errors of kind [`io::ErrorKind::Interrupted`] are automatically retried.
/// * **Partial Lines:** Any data at the end of the stream that is not terminated by a newline
///   is **discarded** and not passed to the processor.
/// * **Early Termination:** `line_processor` can stop the scan early by returning
///   `Ok(ControlFlow::Break(()))`.
///
/// # Returns
///
/// * `Ok(ControlFlow::Continue(()))` — the scan reached EOF normally.
/// * `Ok(ControlFlow::Break(()))` — the scan was stopped early by `line_processor`.
///
/// # Errors
///
/// Returns an [`io::Error`] if:
/// * A line is longer than `buff.len()` (returns [`io::ErrorKind::InvalidData`]).
/// * The underlying reader returns a non-recoverable error.
/// * `line_processor` returns an error.
pub fn scan_lines<R, P>(
    reader: &mut R,
    buff: &mut [u8],
    mut line_processor: P,
) -> io::Result<ControlFlow<()>>
where
    R: Read,
    P: LineProcessor,
{
    // `bytes_in_buff` accounts for the total amount of data currently present in `buff`.
    let mut bytes_in_buff = 0usize;
    loop {
        let read_bytes = match reader.read(&mut buff[bytes_in_buff..]) {
            Ok(0) => return Ok(ControlFlow::Continue(())),
            Ok(read_bytes) => read_bytes,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        bytes_in_buff += read_bytes;

        // Iterate over each line and pass them to the line processor. If no '\n' is found,
        // `processed_data_len` remains 0 and the below shifting logic doesn't run.
        let mut processed_data_len = 0;
        for chunk in buff[..bytes_in_buff].split_inclusive(|&c| c == b'\n') {
            // Don't process lines with no trailing '\n' (this can only be the last line).
            if !chunk.ends_with(&[b'\n']) {
                break;
            }

            // Strip the trailing '\n' from chunk and pass the resulting line to the processor.
            let line = &chunk[..chunk.len() - 1];
            if let ControlFlow::Break(b) = line_processor.process(line)? {
                return Ok(ControlFlow::Break(b));
            }
            processed_data_len += chunk.len();
        }

        // Shift unprocessed data at the beginning of `buff`. This logic only runs if there's
        // actually some unprocessed data, and we have processed at least some lines in this
        // iteration.
        let unprocessed_data_len = bytes_in_buff - processed_data_len;
        if unprocessed_data_len > 0 && processed_data_len > 0 {
            buff.copy_within(processed_data_len..bytes_in_buff, 0);
        }
        bytes_in_buff = unprocessed_data_len;

        // Don't manage line longer total `buff` size.
        if bytes_in_buff == buff.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor, Read};

    /// A reader returning [io::Error::Interrupted] the first time `read()` is invoked.
    struct InterruptedReader<R: Read> {
        inner: R,
        interrupted: bool,
    }

    impl<R: Read> Read for InterruptedReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            self.inner.read(buf)
        }
    }

    /// A reader that strictly reads `chunk_size` bytes at a time. This forces `exact()` to loop
    /// multiple times to fill the buffer.
    struct ChunkedReader<R: Read> {
        inner: R,
        chunk_size: usize,
    }

    impl<R: Read> Read for ChunkedReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = std::cmp::min(buf.len(), self.chunk_size);
            self.inner.read(&mut buf[..len])
        }
    }

    /// A reader that always returns an unrecoverable error.
    struct ErrorReader;

    impl Read for ErrorReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Other, "Unrecoverable error"))
        }
    }

    #[test]
    fn test_exact_happy_path() {
        let input = b"1234567890";
        let mut reader = Cursor::new(input);
        let mut buff = [0u8; 5];
        let read_bytes = exact(&mut reader, &mut buff).unwrap();
        assert_eq!(read_bytes, 5);
        assert_eq!(&buff, b"12345");
        assert_eq!(reader.position(), 5);
    }

    #[test]
    fn test_exact_input_shorter_than_buff() {
        let input = b"123";
        let mut reader = Cursor::new(input);
        let mut buff = [0u8; 5];
        let read_bytes = exact(&mut reader, &mut buff).unwrap();
        assert_eq!(read_bytes, 3);
        assert_eq!(&buff[..3], b"123");
        assert_eq!(buff[3], 0);
    }

    #[test]
    fn test_exact_empty_input() {
        let input = b"";
        let mut reader = Cursor::new(input);
        let mut buff = [0u8; 5];
        let read_bytes = exact(&mut reader, &mut buff).unwrap();
        assert_eq!(read_bytes, 0);
    }

    #[test]
    fn test_exact_interrupted_reads() {
        let input = b"12345";
        let mut reader = InterruptedReader {
            inner: Cursor::new(input),
            interrupted: false,
        };
        let mut buff = [0u8; 5];
        let read_bytes = exact(&mut reader, &mut buff).unwrap();
        assert_eq!(read_bytes, 5);
        assert_eq!(&buff, b"12345");
        assert!(reader.interrupted);
    }

    #[test]
    fn test_exact_chunked_reads() {
        let input = b"123456";
        let mut reader = ChunkedReader {
            inner: Cursor::new(input),
            chunk_size: 2,
        };
        let mut buff = [0u8; 6];
        let read_bytes = exact(&mut reader, &mut buff).unwrap();
        assert_eq!(read_bytes, 6);
        assert_eq!(&buff, b"123456");
    }

    #[test]
    fn test_exact_input_shorter_than_buff_chunked_reads() {
        // Chunked reader, but runs out of data before buffer is full.
        let input = b"123";
        let mut reader = ChunkedReader {
            inner: Cursor::new(input),
            chunk_size: 1, // Read 1 byte at a time
        };
        let mut buff = [0u8; 5];

        let n = exact(&mut reader, &mut buff).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buff[..3], b"123");
    }

    #[test]
    fn test_exact_fails_on_unrecoverable_error() {
        let mut reader = ErrorReader;
        let mut buff = [0u8; 5];

        let res = exact(&mut reader, &mut buff);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::Other);
    }

    /// The size of the scratch buffer provided to `scan_lines()`.
    const SCRATCH_BUFF_SIZE: usize = 4096;

    /// Collects first `n` lines read from `reader` (or all, if `reader` outputs fewer lines) into a
    /// vector of strings. Returns the vector of strings and the [`ControlFlow`] object indicating
    /// whether the scan was interrupted after `n` lines were collected.
    fn collect_first_n_lines_from_reader<R: Read>(
        mut reader: R,
        n: usize,
    ) -> io::Result<(Vec<String>, ControlFlow<()>)> {
        let mut lines = Vec::new();
        let mut buff = [0u8; SCRATCH_BUFF_SIZE];
        let mut counter = 0;
        let cf = scan_lines(&mut reader, &mut buff, |line: &[u8]| {
            lines.push(String::from_utf8_lossy(line).to_string());
            counter += 1;
            if counter < n {
                Ok(ControlFlow::Continue(()))
            } else {
                Ok(ControlFlow::Break(()))
            }
        })?;

        Ok((lines, cf))
    }

    /// Collects first `n` lines read from `input` (or all, if `input` has fewer lines) into a
    /// vector of strings. Returns the vector of strings and the [`ControlFlow`] object indicating
    /// whether the scan was interrupted after `n` lines were collected.
    fn collect_first_n_lines(input: &[u8], n: usize) -> io::Result<(Vec<String>, ControlFlow<()>)> {
        let reader = Cursor::new(input);
        collect_first_n_lines_from_reader(reader, n)
    }

    /// Collects all lines read from `reader` into a vector of strings. It asserts that
    /// [`scan_lines`] is not interrupted by the line processor.
    fn collect_lines_from_reader<R: Read>(reader: R) -> io::Result<Vec<String>> {
        let (lines, cw) = collect_first_n_lines_from_reader(reader, usize::MAX)?;
        assert!(
            cw.is_continue(),
            "expected scan to reach EOF, but LineProcessor interrupted it"
        );
        Ok(lines)
    }

    /// Collects all lines read from `input` into a vector of strings. It asserts that
    /// [`scan_lines`] is not interrupted by the line processor.
    fn collect_lines(input: &[u8]) -> io::Result<Vec<String>> {
        let reader = Cursor::new(input);
        collect_lines_from_reader(reader)
    }

    #[test]
    fn test_scan_lines_happy_path() {
        let input = b"line1\nline2\nline3\n";
        let lines = collect_lines(input).unwrap();
        assert_eq!(lines, vec!["line1", "line2", "line3"]);
    }

    #[test]
    fn test_scan_lines_empty_input() {
        let input = b"";
        let lines = collect_lines(input).unwrap();
        assert!(lines.is_empty());
    }

    #[test]
    fn test_scan_lines_preserves_empty_lines() {
        let input = b"line1\n\nline3\n";
        let lines = collect_lines(input).unwrap();
        assert_eq!(lines, vec!["line1", "", "line3"]);
    }

    #[test]
    fn test_scan_lines_ignores_partial_line_at_eof() {
        let input = b"line1\nline_ignored";
        let lines = collect_lines(input).unwrap();
        assert_eq!(lines, vec!["line1"]);
    }

    #[test]
    fn test_scan_lines_exact_buffer_limit() {
        // Create a line which size (including '\n') is equal to the upper limit.
        let mut input = vec![b'a'; SCRATCH_BUFF_SIZE - 1];
        input.push(b'\n');
        let lines = collect_lines(&input).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].len(), SCRATCH_BUFF_SIZE - 1);
    }

    #[test]
    fn test_scan_lines_exceeds_buffer_limit() {
        // Create a line which size (including '\n') is above the upper limit.
        let input = vec![b'a'; SCRATCH_BUFF_SIZE + 1];
        let result = collect_lines(&input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_scan_lines_sliding_window_logic() {
        let input = b"part1 part2\n";
        let reader = ChunkedReader {
            inner: Cursor::new(input.to_vec()),
            chunk_size: 5,
        };
        let lines = collect_lines_from_reader(reader).unwrap();
        assert_eq!(lines, vec!["part1 part2"]);
    }

    #[test]
    fn test_scan_lines_handles_interrupted_error() {
        let input = b"line\n";
        let reader = InterruptedReader {
            inner: Cursor::new(input.to_vec()),
            interrupted: false,
        };
        let lines = collect_lines_from_reader(reader).unwrap();
        assert_eq!(lines, vec!["line"]);
    }

    #[test]
    fn test_scan_lines_respects_control_flow() {
        let input = b"line1\nline2\nline3\nline4\n";
        let (lines, cw) = collect_first_n_lines(input, 2).unwrap();
        assert_eq!(lines, vec!["line1", "line2"]);
        assert!(cw.is_break());
    }
}
