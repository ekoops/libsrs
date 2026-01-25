use crate::task::Comm;
use std::fs::File;
use std::io;

pub fn read_comm(mut file: File) -> io::Result<Comm> {
    Comm::from_writer(|buff| -> io::Result<usize> {
        let mut read_bytes = crate::read::read_exact(&mut file, buff)?;
        if read_bytes > 0 && buff[read_bytes - 1] == b'\n' {
            read_bytes -= 1;
        }
        Ok(read_bytes)
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn comm_from_file() {
        let file = File::open("/proc/self/comm").unwrap();
        let _comm = read_comm(file).unwrap();
    }
}