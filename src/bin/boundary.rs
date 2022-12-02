use std::fmt::Write;

use time::OffsetDateTime;

use cirith_ungol::CuErr;

const OFFSET: u32 = b'!' as u32;
const RANGE: u32 = (b'~' - b'!') as u32;

fn rando_chars<W: Write>(mut w: W, quartets: usize) -> Result<(), std::fmt::Error> {
    let nanos = OffsetDateTime::now_utc().nanosecond();
    let mut remainder: u32 = 0;

    for _ in 0..quartets {
        let mut left = nanos + remainder;
        remainder = left % RANGE;
        left = left / RANGE;
        for _ in 0..3 {
            let ch: u8 = (remainder + OFFSET) as u8;
            w.write_char(ch as char)?;
            left = left + remainder;
            remainder = left % RANGE;
            left = left / RANGE;
        }
        let ch: u8 = (left + OFFSET) as u8;
        w.write_char(ch as char)?;
    }
    Ok(())
}

fn boundary_string(quartets: usize) -> Result<String, CuErr> {
    let mut s = String::with_capacity(quartets * 4);
    rando_chars(&mut s, quartets).map_err(|e| format!("{}", &e))?;
    Ok(s)
}

fn main() {
    let s = boundary_string(16).unwrap();
    println!("{}", &s);
}