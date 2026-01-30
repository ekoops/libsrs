use lexical_core::FromLexical;
use std::io;

fn strip_ws(buff: &[u8]) -> &[u8] {
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

/// Parse an integer value from `buff`.
///
/// Leading ASCII whitespaces are skipped. Lenient to trailing non-digit ASCII characters.
pub fn value<T: FromLexical>(buff: &[u8]) -> io::Result<T> {
    let stripped_buff = strip_ws(buff);
    let (value, parsed_bytes) =
        lexical_core::parse_partial(stripped_buff).map_err(map_err_invalid)?;
    if parsed_bytes == 0 {
        return Err(err_no_digits());
    }
    Ok(value)
}

/// Strictly parse an integer value from `buff`.
///
/// This variant returns an error for any non-digit ASCII character.
pub fn value_strict<T: FromLexical>(buff: &[u8]) -> io::Result<T> {
    lexical_core::parse(buff).map_err(map_err_invalid)
}

/// Parse an integer value from `*buff` and move `*buff` to the first non-parsed character.
///
/// Leading ASCII whitespaces are skipped. Lenient to trailing non-digit ASCII characters. If an
/// error occurs, `*buff` is not updated.
pub fn next<T: FromLexical>(buff: &mut &[u8]) -> io::Result<T> {
    let stripped_buff = strip_ws(*buff);
    let (value, parsed_bytes) =
        lexical_core::parse_partial(stripped_buff).map_err(map_err_invalid)?;
    if parsed_bytes == 0 {
        return Err(err_no_digits());
    }
    *buff = &stripped_buff[parsed_bytes..];
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_happy_path() {
        assert_eq!(value::<u32>(b"123").unwrap(), 123);
        assert_eq!(value::<i32>(b"-123").unwrap(), -123);
    }

    #[test]
    fn test_value_skips_leading_whitespace() {
        assert_eq!(value::<u32>(b"   123").unwrap(), 123);
        assert_eq!(value::<u32>(b"\t\t123").unwrap(), 123);
    }

    #[test]
    fn test_value_is_lenient_trailing() {
        assert_eq!(value::<u32>(b"123 abc").unwrap(), 123);
        assert_eq!(value::<u32>(b"123\n").unwrap(), 123);
    }

    #[test]
    fn test_value_fails() {
        assert!(value::<u32>(b"").is_err());
        assert!(value::<u32>(b"   ").is_err());
        assert!(value::<u32>(b"abc").is_err());
        assert!(value::<u8>(b"300").is_err());
    }

    #[test]
    fn test_value_strict_happy_path() {
        assert_eq!(value_strict::<u32>(b"123").unwrap(), 123);
    }

    #[test]
    fn test_value_strict_fails_on_whitespace() {
        assert!(value_strict::<u32>(b" 123").is_err());
        assert!(value_strict::<u32>(b"123 ").is_err());
        assert!(value_strict::<u32>(b"123\n").is_err());
    }

    #[test]
    fn test_value_strict_fails_on_suffix() {
        assert!(value_strict::<u32>(b"123kB").is_err());
    }

    #[test]
    fn test_next_advances_cursor() {
        let mut buff: &[u8] = b"10 20 30";
        let v1: u32 = next(&mut buff).unwrap();
        assert_eq!(v1, 10);
        assert_eq!(buff, b" 20 30");
        let v2: u32 = next(&mut buff).unwrap();
        assert_eq!(v2, 20);
        assert_eq!(buff, b" 30");
        let v3: u32 = next(&mut buff).unwrap();
        assert_eq!(v3, 30);
        assert_eq!(buff, b"");
    }

    #[test]
    fn test_next_handles_mixed_delimiters() {
        let mut buff: &[u8] = b"\t100  -50";
        let v1: u32 = next(&mut buff).unwrap();
        assert_eq!(v1, 100);
        let v2: i32 = next(&mut buff).unwrap();
        assert_eq!(v2, -50);
    }

    #[test]
    fn test_next_does_not_advance_on_error() {
        let buff: &[u8] = b"invalid 123";
        let mut temp = buff;
        let res = next::<u32>(&mut temp);
        assert!(res.is_err());
        assert_eq!(temp, buff);
    }

    #[test]
    fn test_next_stops_at_non_digit() {
        let mut buff: &[u8] = b"123kB";
        let val: u32 = next(&mut buff).unwrap();
        assert_eq!(val, 123);
        assert_eq!(buff, b"kB");
    }
}
