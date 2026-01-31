use lexical_core::{FromLexicalWithOptions, NumberFormatBuilder};
use std::io;

/// Return a subslice of `buff` with any leading ASCII whitespace removed.
fn strip_ascii_whitespaces(buff: &[u8]) -> &[u8] {
    match buff.iter().position(|c| !c.is_ascii_whitespace()) {
        Some(pos) => &buff[pos..],
        None => &[],
    }
}

fn map_err_invalid(_: lexical_core::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid number")
}

fn err_no_digits() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "no digits to parse")
}

/// Parse an integer formatted according to [FORMAT] from `buff`.
///
/// Leading ASCII whitespaces are skipped. Lenient to trailing non-digit ASCII characters.
fn parse_with_format<T, const FORMAT: u128>(buff: &[u8]) -> io::Result<T>
where
    T: FromLexicalWithOptions,
{
    let stripped_buff = strip_ascii_whitespaces(buff);
    let options = T::Options::default();
    let (value, parsed_bytes) =
        lexical_core::parse_partial_with_options::<T, FORMAT>(stripped_buff, &options)
            .map_err(map_err_invalid)?;
    if parsed_bytes == 0 {
        Err(err_no_digits())
    } else {
        Ok(value)
    }
}

/// Strictly parse an integer formatted according to [FORMAT] from `buff`.
///
/// This variant returns an error for any non-digit ASCII character.
fn parse_strict_with_format<T, const FORMAT: u128>(buff: &[u8]) -> io::Result<T>
where
    T: FromLexicalWithOptions,
{
    let options = T::Options::default();
    lexical_core::parse_with_options::<T, FORMAT>(buff, &options).map_err(map_err_invalid)
}

/// Parse an integer formatted according to [FORMAT] from `*buff` and move `*buff` to the first
/// non-parsed character.
///
/// Leading ASCII whitespaces are skipped. Lenient to trailing non-digit ASCII characters. If an
/// error occurs, `*buff` is not updated.
fn next_with_format<T, const FORMAT: u128>(buff: &mut &[u8]) -> io::Result<T>
where
    T: FromLexicalWithOptions,
{
    let stripped_buff = strip_ascii_whitespaces(*buff);
    let options = T::Options::default();
    let (value, parsed_bytes) =
        lexical_core::parse_partial_with_options::<T, FORMAT>(stripped_buff, &options)
            .map_err(map_err_invalid)?;
    if parsed_bytes == 0 {
        return Err(err_no_digits());
    }
    *buff = &stripped_buff[parsed_bytes..];
    Ok(value)
}

/// Format for base-10 number parsing. See [dec] for details.
const DEC_FORMAT: u128 = NumberFormatBuilder::decimal();
/// Format for base-16 number parsing. See [hex] for details.
const HEX_FORMAT: u128 = NumberFormatBuilder::hexadecimal();
/// Format for base-8 number parsing. See [oct] for details.
const OCT_FORMAT: u128 = NumberFormatBuilder::octal();
/// Format for base-2 number parsing. See [bin] for details.
const BIN_FORMAT: u128 = NumberFormatBuilder::binary();

/// Parse a decimal integer from `buff`.
///
/// # Format Rules
///
/// * **Prefix:** Leading `0`s are skipped.
/// * **Whitespace:** Leading ASCII whitespaces are skipped.
/// * **Trailing:** Lenient to trailing non-decimal digit ASCII characters.
pub fn dec<T: FromLexicalWithOptions>(buff: &[u8]) -> io::Result<T> {
    parse_with_format::<T, DEC_FORMAT>(buff)
}

/// Parse a hexadecimal integer from `buff`.
///
/// # Format Rules
///
/// * **Case:** Case-insensitive (accepts `a-f` and `A-F`).
/// * **Prefix:** Leading `0`s are skipped while leading `0x` is not (parsed as `0`).
/// * **Whitespace:** Leading ASCII whitespaces are skipped.
/// * **Trailing:** Lenient to trailing non-hexadecimal digit ASCII characters.
pub fn hex<T: FromLexicalWithOptions>(buff: &[u8]) -> io::Result<T> {
    parse_with_format::<T, HEX_FORMAT>(buff)
}

/// Parse an octal integer from `buff`.
///
/// # Format Rules
///
/// * **Prefix:** Leading `0`s are skipped while leading `0o` is not (parsed as `0`).
/// * **Whitespace:** Leading ASCII whitespaces are skipped.
/// * **Trailing:** Lenient to trailing non-octal digit ASCII characters.
pub fn oct<T: FromLexicalWithOptions>(buff: &[u8]) -> io::Result<T> {
    parse_with_format::<T, OCT_FORMAT>(buff)
}

/// Parse a binary integer from `buff`.
///
/// # Format Rules
///
/// * **Prefix:** Leading `0`s are skipped while leading `0b` is not (parsed as `0`).
/// * **Whitespace:** Leading ASCII whitespaces are skipped.
/// * **Trailing:** Lenient to trailing non-binary digit ASCII characters.
pub fn bin<T: FromLexicalWithOptions>(buff: &[u8]) -> io::Result<T> {
    parse_with_format::<T, BIN_FORMAT>(buff)
}

/// Strictly parse a decimal integer from `buff`.
///
/// Same format rules as [dec] expects that returns an error for **any** non-decimal digit ASCII
/// character.
pub fn dec_strict<T: FromLexicalWithOptions>(buff: &[u8]) -> io::Result<T> {
    parse_strict_with_format::<T, DEC_FORMAT>(buff)
}

/// Strictly parse a hexadecimal integer from `buff`.
///
/// # Format Rules
///
/// Same as [hex] excepts that returns an error for **any** non-hexadecimal digit ASCII character.
pub fn hex_strict<T: FromLexicalWithOptions>(buff: &[u8]) -> io::Result<T> {
    parse_strict_with_format::<T, HEX_FORMAT>(buff)
}

/// Strictly parse an octal integer from `buff`.
///
/// # Format Rules
///
/// Same as [oct] excepts that returns an error for **any** non-octal digit ASCII character.
pub fn oct_strict<T: FromLexicalWithOptions>(buff: &[u8]) -> io::Result<T> {
    parse_strict_with_format::<T, OCT_FORMAT>(buff)
}

/// Strictly parse a binary integer from `buff`.
///
/// # Format Rules
///
/// Same as [bin] excepts that returns an error for **any** non-binary digit ASCII character.
pub fn bin_strict<T: FromLexicalWithOptions>(buff: &[u8]) -> io::Result<T> {
    parse_strict_with_format::<T, BIN_FORMAT>(buff)
}

/// Parse a decimal integer from `*buff` and move `*buff` to the first non-parsed character.
///
/// If an error occurs, `*buff` is not updated.
///
/// # Format Rules
///
/// Same as [dec].
pub fn next_dec<T: FromLexicalWithOptions>(buff: &mut &[u8]) -> io::Result<T> {
    next_with_format::<T, DEC_FORMAT>(buff)
}

/// Parse a hexadecimal integer from `*buff` and move `*buff` to the first non-parsed character.
///
/// If an error occurs, `*buff` is not updated.
///
/// # Format Rules
///
/// Same as [hex].
pub fn next_hex<T: FromLexicalWithOptions>(buff: &mut &[u8]) -> io::Result<T> {
    next_with_format::<T, HEX_FORMAT>(buff)
}

/// Parse an octal integer from `*buff` and move `*buff` to the first non-parsed character.
///
/// If an error occurs, `*buff` is not updated.
///
/// # Format Rules
///
/// Same as [oct].
pub fn next_oct<T: FromLexicalWithOptions>(buff: &mut &[u8]) -> io::Result<T> {
    next_with_format::<T, OCT_FORMAT>(buff)
}

/// Parse an integer from `*buff` and move `*buff` to the first non-parsed character.
///
/// If an error occurs, `*buff` is not updated.
///
/// # Format Rules
///
/// Same as [bin].
pub fn next_bin<T: FromLexicalWithOptions>(buff: &mut &[u8]) -> io::Result<T> {
    next_with_format::<T, BIN_FORMAT>(buff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dec_hex_oct_bin_happy_path() {
        assert_eq!(dec::<u32>(b"123").unwrap(), 123);
        assert_eq!(dec::<i32>(b"-123").unwrap(), -123);
        assert_eq!(hex::<u32>(b"abc").unwrap(), 0xabc);
        assert_eq!(hex::<i32>(b"-abc").unwrap(), -0xabc);
        assert_eq!(oct::<u32>(b"777").unwrap(), 0o777);
        assert_eq!(oct::<i32>(b"-777").unwrap(), -0o777);
        assert_eq!(bin::<u32>(b"101").unwrap(), 0b101);
        assert_eq!(bin::<i32>(b"-101").unwrap(), -0b101);
    }

    #[test]
    fn hex_case_insensitive() {
        assert_eq!(hex::<u32>(b"AbC").unwrap(), 0xabc);
    }

    #[test]
    fn dec_hex_oct_bin_skip_leading_zeroes() {
        assert_eq!(hex::<u32>(b"000abc").unwrap(), 0xabc);
        assert_eq!(oct::<u32>(b"000777").unwrap(), 0o777);
        assert_eq!(bin::<u32>(b"000101").unwrap(), 0b101);
    }

    #[test]
    fn dec_hex_oct_bin_skip_leading_whitespace() {
        assert_eq!(dec::<u32>(b"   123").unwrap(), 123);
        assert_eq!(dec::<u32>(b"\t\t123").unwrap(), 123);
        assert_eq!(hex::<u32>(b"   abc").unwrap(), 0xabc);
        assert_eq!(hex::<i32>(b"\t\tabc").unwrap(), 0xabc);
        assert_eq!(oct::<u32>(b"   777").unwrap(), 0o777);
        assert_eq!(oct::<i32>(b"\t\t777").unwrap(), 0o777);
        assert_eq!(bin::<u32>(b"   101").unwrap(), 0b101);
        assert_eq!(bin::<i32>(b"\t\t101").unwrap(), 0b101);
    }

    #[test]
    fn dec_hex_oct_bin_are_lenient_trailing() {
        assert_eq!(dec::<u32>(b"123 abc").unwrap(), 123);
        assert_eq!(dec::<u32>(b"123\n").unwrap(), 123);
        assert_eq!(hex::<u32>(b"abc abc").unwrap(), 0xabc);
        assert_eq!(hex::<i32>(b"abc\n").unwrap(), 0xabc);
        assert_eq!(oct::<u32>(b"777 abc").unwrap(), 0o777);
        assert_eq!(oct::<i32>(b"777\n").unwrap(), 0o777);
        assert_eq!(bin::<u32>(b"101 abc").unwrap(), 0b101);
        assert_eq!(bin::<i32>(b"101\n").unwrap(), 0b101);
    }

    #[test]
    fn dec_hex_oct_bin_fail() {
        assert!(dec::<u32>(b"").is_err());
        assert!(dec::<u32>(b"   ").is_err());
        assert!(dec::<u32>(b"abc").is_err());
        assert!(dec::<u8>(b"300").is_err());
        assert!(hex::<u32>(b"").is_err());
        assert!(hex::<u32>(b"   ").is_err());
        assert!(hex::<u32>(b"ghi").is_err());
        assert!(hex::<u8>(b"abc").is_err());
        assert!(oct::<u32>(b"").is_err());
        assert!(oct::<u32>(b"   ").is_err());
        assert!(oct::<u32>(b"abc").is_err());
        assert!(oct::<u8>(b"777").is_err());
        assert!(bin::<u32>(b"").is_err());
        assert!(bin::<u32>(b"   ").is_err());
        assert!(bin::<u32>(b"abc").is_err());
        assert!(bin::<u8>(b"100000000").is_err());
    }

    #[test]
    fn dec_hex_oct_bin_strict_happy_path() {
        assert_eq!(dec_strict::<u32>(b"123").unwrap(), 123);
        assert_eq!(dec_strict::<i32>(b"-123").unwrap(), -123);
        assert_eq!(hex_strict::<u32>(b"abc").unwrap(), 0xabc);
        assert_eq!(hex_strict::<i32>(b"-abc").unwrap(), -0xabc);
        assert_eq!(oct_strict::<u32>(b"777").unwrap(), 0o777);
        assert_eq!(oct_strict::<i32>(b"-777").unwrap(), -0o777);
        assert_eq!(bin_strict::<u32>(b"101").unwrap(), 0b101);
        assert_eq!(bin_strict::<i32>(b"-101").unwrap(), -0b101);
    }

    #[test]
    fn hex_strict_case_insensitive() {
        assert_eq!(hex_strict::<u32>(b"AbC").unwrap(), 0xabc);
    }

    #[test]
    fn dec_hex_oct_bin_strict_skip_leading_zeroes() {
        assert_eq!(hex_strict::<u32>(b"000abc").unwrap(), 0xabc);
        assert_eq!(oct_strict::<u32>(b"000777").unwrap(), 0o777);
        assert_eq!(bin_strict::<u32>(b"000101").unwrap(), 0b101);
    }

    #[test]
    fn dec_hex_oct_bin_strict_fail_on_whitespace() {
        assert!(dec_strict::<u32>(b"   123").is_err());
        assert!(dec_strict::<u32>(b"\t\t123").is_err());
        assert!(hex_strict::<u32>(b"   abc").is_err());
        assert!(hex_strict::<i32>(b"\t\tabc").is_err());
        assert!(oct_strict::<u32>(b"   777").is_err());
        assert!(oct_strict::<i32>(b"\t\t777").is_err());
        assert!(bin_strict::<u32>(b"   101").is_err());
        assert!(bin_strict::<i32>(b"\t\t101").is_err());
    }

    #[test]
    fn dec_hex_oct_bin_strict_fail_on_suffix() {
        assert!(dec_strict::<u32>(b"123kB").is_err());
        assert!(dec_strict::<u32>(b"123\n").is_err());
        assert!(hex_strict::<u32>(b"abckB").is_err());
        assert!(hex_strict::<i32>(b"abc\n").is_err());
        assert!(oct_strict::<u32>(b"777kB").is_err());
        assert!(oct_strict::<i32>(b"777\n").is_err());
        assert!(bin_strict::<u32>(b"101kB").is_err());
        assert!(bin_strict::<i32>(b"101\n").is_err());
    }

    #[test]
    fn test_next_dec_hex_oct_bin_advance_cursor() {
        let mut buff: &[u8] = b"10 abc 777 101";
        let v1: u32 = next_dec(&mut buff).unwrap();
        assert_eq!(v1, 10);
        assert_eq!(buff, b" abc 777 101");
        let v2: u32 = next_hex(&mut buff).unwrap();
        assert_eq!(v2, 0xabc);
        assert_eq!(buff, b" 777 101");
        let v3: u32 = next_oct(&mut buff).unwrap();
        assert_eq!(v3, 0o777);
        assert_eq!(buff, b" 101");
        let v4: u32 = next_bin(&mut buff).unwrap();
        assert_eq!(v4, 0b101);
        assert_eq!(buff, b"");
    }

    #[test]
    fn test_next_dec_hex_oct_bin_handle_mixed_delimiters() {
        let mut buff: &[u8] = b"\t10  abc\n777\t\t101";
        let v1: u32 = next_dec(&mut buff).unwrap();
        assert_eq!(v1, 10);
        assert_eq!(buff, b"  abc\n777\t\t101");
        let v2: u32 = next_hex(&mut buff).unwrap();
        assert_eq!(v2, 0xabc);
        assert_eq!(buff, b"\n777\t\t101");
        let v3: u32 = next_oct(&mut buff).unwrap();
        assert_eq!(v3, 0o777);
        assert_eq!(buff, b"\t\t101");
        let v4: u32 = next_bin(&mut buff).unwrap();
        assert_eq!(v4, 0b101);
        assert_eq!(buff, b"");
    }

    #[test]
    fn test_next_dec_hex_oct_bin_do_not_advance_on_error() {
        let buff: &[u8] = b"invalid 111";
        let mut temp = buff;
        let res = next_dec::<u32>(&mut temp);
        assert!(res.is_err());
        assert_eq!(temp, buff);
        let res = next_hex::<u32>(&mut temp);
        assert!(res.is_err());
        assert_eq!(temp, buff);
        let res = next_oct::<u32>(&mut temp);
        assert!(res.is_err());
        assert_eq!(temp, buff);
        let res = next_bin::<u32>(&mut temp);
        assert!(res.is_err());
        assert_eq!(temp, buff);
    }

    #[test]
    fn test_next_dec_hex_oct_bin_stop_at_non_digit() {
        let buff: &[u8] = b"111kB";
        let mut temp = buff;
        let res = next_dec::<u32>(&mut temp).unwrap();
        assert_eq!(res, 111);
        assert_eq!(temp, b"kB");
        let mut temp = buff;
        let res = next_hex::<u32>(&mut temp).unwrap();
        assert_eq!(res, 0x111);
        assert_eq!(temp, b"kB");
        let mut temp = buff;
        let res = next_oct::<u32>(&mut temp).unwrap();
        assert_eq!(res, 0o111);
        assert_eq!(temp, b"kB");
        let mut temp = buff;
        let res = next_bin::<u32>(&mut temp).unwrap();
        assert_eq!(res, 0b111);
        assert_eq!(temp, b"kB");
    }
}
