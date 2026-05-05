use lexical_core::{NumberFormatBuilder, ToLexicalWithOptions};

/// Updates `*buff` to point to `len` bytes forward.
fn advance(buff: &mut &mut [u8], len: usize) {
    let (_, new_buff) = std::mem::take(buff).split_at_mut(len);
    *buff = new_buff;
}

/// Format for base-10 number writing. See [next_dec] for details.
const DEC_FORMAT: u128 = NumberFormatBuilder::decimal();

/// Writes `num` according to [FORMAT] into `*buff` and returns the number of bytes written. Updates
/// `*buff` to point to the first unwritten byte.
fn next_with_format<'a, 'b: 'a, N: ToLexicalWithOptions, const FORMAT: u128>(
    buff: &'a mut &'b mut [u8],
    num: N,
) -> usize {
    let options = N::Options::default();
    let num_bytes = lexical_core::write_with_options::<N, FORMAT>(num, buff, &options);
    let written_bytes = num_bytes.len();
    advance(buff, written_bytes);
    written_bytes
}

/// Writes a decimal representation of `num` into `*buff` and returns the number of bytes written.
/// Updates `*buff` to point to the first unwritten byte.
pub fn next_dec<'a, 'b: 'a, N: ToLexicalWithOptions>(buff: &'a mut &'b mut [u8], num: N) -> usize {
    next_with_format::<N, DEC_FORMAT>(buff, num)
}

/// Writes `bytes` in `*buff` and returns `bytes.len()`. Updates `*buff` to point to the first
/// unwritten byte.
pub fn next_bytes(buff: &mut &mut [u8], bytes: &[u8]) -> usize {
    let bytes_len = bytes.len();
    buff[..bytes_len].copy_from_slice(bytes);
    advance(buff, bytes_len);
    bytes_len
}