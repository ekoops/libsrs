use libc::c_char;
use std::ffi::CStr;
use std::io::{self, Read};

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
    /// Process a line of data.
    fn process(&mut self, line: &[u8]);
}

/// Blanket implementation allowing the use of closures as [LineProcessor].
impl<F> LineProcessor for F
where
    F: FnMut(&[u8]),
{
    fn process(&mut self, line: &[u8]) {
        self(line)
    }
}

/// The maximum amount of bytes that a line can contain (including the trailing '\n') while
/// processed by [scan_lines]. Note: this is intentionally kept small to be suitable for a stack
/// allocation.
pub const MAX_SCAN_LINE_LEN: usize = 4096;

/// Efficiently read all lines from `reader`, passing them to `line_processor` for processing. Lines
/// are read till `reader` returns 0 as the number of bytes read. Any error of kind
/// [io::ErrorKind::Interrupted] is handled by restarting the read operation. Lines bigger than
/// [MAX_SCAN_LINE_LEN] results in a [io::ErrorKind::InvalidData] kind of error. Each line is passed
/// to `line_processor` without the trailing '\n' character. Any trailing line with no trailing `\n`
/// character is not provided to `line_processor`.
pub fn scan_lines<R, P>(reader: &mut R, mut line_processor: P) -> io::Result<()>
where
    R: Read,
    P: LineProcessor,
{
    let mut buff = [0u8; MAX_SCAN_LINE_LEN];
    // `bytes_in_buff` accounts for the total amount of data currently present in `buff`.
    let mut bytes_in_buff = 0usize;
    loop {
        let read_bytes = match reader.read(&mut buff[bytes_in_buff..]) {
            Ok(0) => return Ok(()),
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
            line_processor.process(line);
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

/// Read the content of the symbolic link `path` into `buff`. Return the amount of data read.
pub fn link(path: &CStr, buff: &mut [u8]) -> io::Result<usize> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor, Read};

    fn collect_lines(input: &[u8]) -> io::Result<Vec<String>> {
        let mut reader = Cursor::new(input);
        let mut lines = Vec::new();

        scan_lines(&mut reader, |line: &[u8]| {
            // Convert bytes to String for easy assertion
            lines.push(String::from_utf8_lossy(line).to_string());
        })?;

        Ok(lines)
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
        let mut input = vec![b'a'; MAX_SCAN_LINE_LEN - 1];
        input.push(b'\n');
        let lines = collect_lines(&input).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].len(), MAX_SCAN_LINE_LEN - 1);
    }

    #[test]
    fn test_scan_lines_exceeds_buffer_limit() {
        // Create a line which size (including '\n') is equal to the upper limit.
        let input = vec![b'a'; MAX_SCAN_LINE_LEN + 1];
        let result = collect_lines(&input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_scan_lines_sliding_window_logic() {
        let input = b"part1 part2\n";
        let lines = collect_lines(input).unwrap();
        assert_eq!(lines, vec!["part1 part2"]);
    }

    #[test]
    fn test_scan_lines_handles_interrupted_error() {
        /// A reader returning [io::Error::Interrupted] the first time `read()` is invoked.
        struct InterruptedReader {
            data: Cursor<Vec<u8>>,
            interrupted_once: bool,
        }

        impl Read for InterruptedReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted_once {
                    self.interrupted_once = true;
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "Interrupted signal",
                    ));
                }
                self.data.read(buf)
            }
        }

        let input = b"line\n";
        let mut reader = InterruptedReader {
            data: Cursor::new(input.to_vec()),
            interrupted_once: false,
        };

        let mut lines = Vec::new();
        let res = scan_lines(&mut reader, |line: &[u8]| {
            lines.push(String::from_utf8_lossy(line).to_string());
        });

        assert!(res.is_ok());
        assert_eq!(lines, vec!["line"]);
    }
}
