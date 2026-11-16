//! The check of a profile picture's JPEG, and the rewrite that makes one
//! (`docs/design/2026-11-profile-pictures.md` §8.2 and §16.2).
//!
//! A friend's picture is shown with no tap, so its bytes reach an image
//! decoder with no act of the user. Image decoders have been the way in for
//! attacks of exactly that kind. This module stands before the decoder: it
//! walks the markers and the lengths of the file and takes only a plain
//! baseline JPEG, square and small, that holds nothing but its tables, its
//! frame and one scan. It decodes nothing, trusts no length, and never reads
//! past the end of the bytes it was given.
//!
//! [`check`] is the receiver's rule, and the rule for what leaves this
//! device. [`clean`] writes a file that an encoder made once more, in the one
//! order `check` takes and without the segments encoders add (Exif, colour
//! profiles, comments). It touches no pixel: the tables and the scan are
//! copied as they are.

use std::fmt;

/// What a picture of one kind may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The smallest side, in pixels.
    pub min_side: u16,
    /// The largest side, in pixels.
    pub max_side: u16,
    /// The most bytes the file may have.
    pub max_len: usize,
}

/// A profile picture: 64 to 512 pixels a side, at most 60,000 bytes (one
/// chunk, [`super::blob::ONE_CHUNK_MAX_LEN`]).
pub const PICTURE: Limits = Limits {
    min_side: 64,
    max_side: 512,
    max_len: 60_000,
};

/// A profile picture's preview: 16 to 64 pixels a side, at most 1,536 bytes
/// ([`super::offer::MAX_PREVIEW_BYTES`]).
pub const PREVIEW: Limits = Limits {
    min_side: 16,
    max_side: 64,
    max_len: 1_536,
};

/// Why a file is not taken. No value holds a byte of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JpegError {
    /// More bytes than a picture of this kind may have.
    TooLong,
    /// A side outside the limits of this kind.
    Side,
    /// Not the plain baseline JPEG this module takes. The words name the
    /// rule, for logs and tests.
    Refused(&'static str),
}

impl fmt::Display for JpegError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JpegError::TooLong => f.write_str("the picture has too many bytes"),
            JpegError::Side => f.write_str("the picture's side is outside the limits"),
            JpegError::Refused(rule) => write!(f, "not a plain baseline JPEG: {rule}"),
        }
    }
}

impl std::error::Error for JpegError {}

/// What [`check`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checked {
    /// The side of the square, in pixels.
    pub side: u16,
    /// 1 (grey) or 3 (colour).
    pub components: u8,
}

const SOI: u8 = 0xD8;
const EOI: u8 = 0xD9;
const SOF0: u8 = 0xC0;
const DHT: u8 = 0xC4;
const DQT: u8 = 0xDB;
const DRI: u8 = 0xDD;
const SOS: u8 = 0xDA;
const APP0: u8 = 0xE0;
const APP14: u8 = 0xEE;
const APP15: u8 = 0xEF;
const COM: u8 = 0xFE;
const RST0: u8 = 0xD0;
const RST7: u8 = 0xD7;

/// The JFIF header this module writes: version 1.01, no unit, 1 to 1, no
/// thumbnail.
const JFIF_APP0: [u8; 18] = [
    0xFF, APP0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00,
];

/// One quantization table: its id and its 64 values.
#[derive(Clone, Copy)]
struct Quant {
    id: u8,
    values: [u8; 64],
}

/// One Huffman table: its class (0 DC, 1 AC), its id, and its bytes as they
/// lie in the file (16 counts, then the symbols).
#[derive(Clone)]
struct Huff {
    class: u8,
    id: u8,
    body: Vec<u8>,
}

#[derive(Clone, Copy)]
struct Component {
    id: u8,
    h: u8,
    v: u8,
    quant: u8,
    dc: u8,
    ac: u8,
}

/// A file that passed the walk: everything [`clean`] writes again.
struct Parsed<'a> {
    quants: Vec<Quant>,
    huffs: Vec<Huff>,
    side: u16,
    components: Vec<Component>,
    restart: u16,
    /// The scan's data, from behind the scan header up to the end marker.
    scan: &'a [u8],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The receiver's rule: the one order, nothing else in the file.
    Strict,
    /// An encoder's file: tables in any order before the scan, and segments
    /// that hold no pixel (other APP segments, comments) passed over.
    Encoder,
}

fn refused<T>(rule: &'static str) -> Result<T, JpegError> {
    Err(JpegError::Refused(rule))
}

/// The receiver's rule. `bytes` is taken only when it is a baseline JPEG in
/// this order and with nothing else: the start marker; one JFIF header with
/// no thumbnail; the quantization tables (8 bit, at most 4, none twice); one
/// baseline frame (8 bit samples; 1 or 3 components; square; a side inside
/// `limits`; the first component sampled 1 or 2 each way and the others 1);
/// the Huffman tables (at most 2 of each class, none twice, counts that make
/// a code, baseline symbols only); at most one restart interval, never 0;
/// exactly one scan with every component in the frame's order and the whole
/// spectrum; in the scan only its data, stuffed bytes and the restart markers
/// in their order and number; the end marker; and not one byte after it.
pub fn check(bytes: &[u8], limits: &Limits) -> Result<Checked, JpegError> {
    let parsed = walk(bytes, limits, Mode::Strict)?;
    Ok(Checked {
        side: parsed.side,
        components: parsed.components.len() as u8,
    })
}

/// Writes a JPEG that an encoder made once more, as [`check`] takes it: the
/// same tables, frame and scan, in the one order, under a plain JFIF header.
/// Segments that hold no pixel are left out. A file whose colours an Adobe
/// segment declares as anything but YCbCr is refused, since leaving that
/// segment out would change them. What comes back has passed [`check`].
pub fn clean(bytes: &[u8], limits: &Limits) -> Result<Vec<u8>, JpegError> {
    let parsed = walk(bytes, limits, Mode::Encoder)?;
    let mut out = Vec::with_capacity(bytes.len().min(limits.max_len) + 64);
    out.extend_from_slice(&[0xFF, SOI]);
    out.extend_from_slice(&JFIF_APP0);
    let mut quants = parsed.quants.clone();
    quants.sort_by_key(|q| q.id);
    for quant in &quants {
        out.extend_from_slice(&[0xFF, DQT, 0x00, 0x43, quant.id]);
        out.extend_from_slice(&quant.values);
    }
    let count = parsed.components.len();
    out.extend_from_slice(&[0xFF, SOF0]);
    out.extend_from_slice(&((8 + 3 * count) as u16).to_be_bytes());
    out.push(8);
    out.extend_from_slice(&parsed.side.to_be_bytes());
    out.extend_from_slice(&parsed.side.to_be_bytes());
    out.push(count as u8);
    for c in &parsed.components {
        out.extend_from_slice(&[c.id, (c.h << 4) | c.v, c.quant]);
    }
    let mut huffs = parsed.huffs.clone();
    huffs.sort_by_key(|h| (h.class, h.id));
    for huff in &huffs {
        out.extend_from_slice(&[0xFF, DHT]);
        out.extend_from_slice(&((3 + huff.body.len()) as u16).to_be_bytes());
        out.push((huff.class << 4) | huff.id);
        out.extend_from_slice(&huff.body);
    }
    if parsed.restart > 0 {
        out.extend_from_slice(&[0xFF, DRI, 0x00, 0x04]);
        out.extend_from_slice(&parsed.restart.to_be_bytes());
    }
    out.extend_from_slice(&[0xFF, SOS]);
    out.extend_from_slice(&((6 + 2 * count) as u16).to_be_bytes());
    out.push(count as u8);
    for c in &parsed.components {
        out.extend_from_slice(&[c.id, (c.dc << 4) | c.ac]);
    }
    out.extend_from_slice(&[0x00, 0x3F, 0x00]);
    out.extend_from_slice(parsed.scan);
    out.extend_from_slice(&[0xFF, EOI]);
    // The header written here is a little shorter or longer than what it
    // replaces, so the length is asked again, with everything else.
    check(&out, limits)?;
    Ok(out)
}

/// The order of the segments before the scan, for [`Mode::Strict`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    Start,
    Header,
    Quant,
    Frame,
    Huff,
    Restart,
}

fn walk<'a>(bytes: &'a [u8], limits: &Limits, mode: Mode) -> Result<Parsed<'a>, JpegError> {
    // An encoder's file may be longer than the picture it holds (the segments
    // left out); it is still bounded, so that a walk is never long.
    let most = match mode {
        Mode::Strict => limits.max_len,
        Mode::Encoder => limits.max_len.saturating_add(ENCODER_EXTRA),
    };
    if bytes.len() > most {
        return Err(JpegError::TooLong);
    }
    if bytes.get(..2) != Some(&[0xFF, SOI]) {
        return refused("no start marker");
    }
    let mut at = 2usize;
    let mut stage = Stage::Start;
    let mut jfif = false;
    let mut adobe: Option<u8> = None;
    let mut quants: Vec<Quant> = Vec::with_capacity(4);
    let mut huffs: Vec<Huff> = Vec::with_capacity(4);
    let mut frame: Option<(u16, Vec<Component>)> = None;
    let mut restart: Option<u16> = None;

    let (mut components, scan_at) = loop {
        if bytes.get(at) != Some(&0xFF) {
            return refused("a marker is missing");
        }
        let mut marker = *bytes.get(at + 1).ok_or(JpegError::Refused("cut short"))?;
        if mode == Mode::Encoder {
            // Fill bytes before a marker.
            while marker == 0xFF {
                at += 1;
                marker = *bytes.get(at + 1).ok_or(JpegError::Refused("cut short"))?;
            }
        }
        let len = match bytes.get(at + 2..at + 4) {
            Some(&[hi, lo]) => usize::from(u16::from_be_bytes([hi, lo])),
            _ => return refused("cut short"),
        };
        if len < 2 {
            return refused("a segment's length");
        }
        let body = bytes
            .get(at + 4..at + 2 + len)
            .ok_or(JpegError::Refused("a segment runs past the end"))?;
        let next = at + 2 + len;
        let step = |stage: &mut Stage, to: Stage, again: bool| -> Result<(), JpegError> {
            if mode == Mode::Strict && (*stage > to || (*stage == to && !again)) {
                return refused("the order of the segments");
            }
            if mode == Mode::Strict || *stage < to {
                *stage = (*stage).max(to);
            }
            Ok(())
        };
        match marker {
            APP0 if is_jfif(body) => {
                if mode == Mode::Strict {
                    if stage != Stage::Start {
                        return refused("the order of the segments");
                    }
                    jfif_plain(body)?;
                    stage = Stage::Header;
                }
                jfif = true;
            }
            DQT => {
                if mode == Mode::Strict && stage < Stage::Header {
                    return refused("no JFIF header");
                }
                step(&mut stage, Stage::Quant, true)?;
                read_quants(body, &mut quants)?;
            }
            SOF0 => {
                if frame.is_some() {
                    return refused("two frames");
                }
                if mode == Mode::Strict && stage != Stage::Quant {
                    return refused("the order of the segments");
                }
                step(&mut stage, Stage::Frame, false)?;
                frame = Some(read_frame(body, limits)?);
            }
            DHT => {
                if mode == Mode::Strict && stage < Stage::Frame {
                    return refused("the order of the segments");
                }
                step(&mut stage, Stage::Huff, true)?;
                read_huffs(body, &mut huffs)?;
            }
            DRI => {
                if restart.is_some() {
                    return refused("two restart intervals");
                }
                if mode == Mode::Strict && stage != Stage::Huff {
                    return refused("the order of the segments");
                }
                step(&mut stage, Stage::Restart, false)?;
                let interval = match body {
                    &[hi, lo] => u16::from_be_bytes([hi, lo]),
                    _ => return refused("the restart interval's length"),
                };
                if interval == 0 && mode == Mode::Strict {
                    return refused("a restart interval of 0");
                }
                restart = Some(interval);
            }
            SOS => {
                if mode == Mode::Strict && stage < Stage::Huff {
                    return refused("the order of the segments");
                }
                let (side, mut components) = frame
                    .take()
                    .ok_or(JpegError::Refused("a scan before its frame"))?;
                read_scan_header(body, &mut components)?;
                frame = Some((side, Vec::new()));
                break (components, next);
            }
            // Segments that hold no pixel. An encoder may add them; a
            // picture that travels has none.
            APP0..=APP15 | COM if mode == Mode::Encoder => {
                if marker == APP14 {
                    if let Some(transform) = adobe_transform(body) {
                        adobe = Some(transform);
                    }
                }
            }
            APP0..=APP15 => return refused("an application segment"),
            COM => return refused("a comment"),
            0xC1..=0xCF => return refused("not a baseline frame"),
            _ => return refused("a marker this picture may not have"),
        }
        at = next;
    };
    let side = frame.map(|(side, _)| side).unwrap_or(0);

    // Every table a component names is in the file.
    for c in &components {
        if !quants.iter().any(|q| q.id == c.quant) {
            return refused("a quantization table is missing");
        }
        if !huffs.iter().any(|h| h.class == 0 && h.id == c.dc)
            || !huffs.iter().any(|h| h.class == 1 && h.id == c.ac)
        {
            return refused("a Huffman table is missing");
        }
    }
    if mode == Mode::Strict && !jfif {
        return refused("no JFIF header");
    }
    if mode == Mode::Encoder && components.len() == 3 {
        // Without a JFIF header and without an Adobe segment a decoder reads
        // three components named R, G and B as RGB; with an Adobe segment its
        // transform byte says so. This module writes a JFIF header and no
        // Adobe segment, which every decoder reads as YCbCr.
        let named_rgb = b"RGB"
            .iter()
            .zip(&components)
            .all(|(name, c)| c.id == *name);
        match adobe {
            Some(1) => {}
            Some(_) => return refused("colours that are not YCbCr"),
            None if named_rgb && !jfif => return refused("colours that are not YCbCr"),
            None => {}
        }
    }
    let restart = restart.unwrap_or(0);

    // The scan: data, stuffed bytes, the restart markers in order, the end.
    let wide = components.len() > 1;
    let (h_max, v_max) = (
        components.iter().map(|c| c.h).max().unwrap_or(1),
        components.iter().map(|c| c.v).max().unwrap_or(1),
    );
    let side_px = usize::from(side);
    let units = if wide {
        side_px.div_ceil(8 * usize::from(h_max)) * side_px.div_ceil(8 * usize::from(v_max))
    } else {
        side_px.div_ceil(8) * side_px.div_ceil(8)
    };
    let blocks: usize = if wide {
        components.iter().map(|c| usize::from(c.h * c.v)).sum()
    } else {
        1
    };
    let restarts_due = if restart == 0 {
        0
    } else {
        units.div_ceil(usize::from(restart)) - 1
    };
    let mut restarts = 0usize;
    let mut look = scan_at;
    let end = loop {
        let found = bytes
            .get(look..)
            .and_then(|rest| rest.iter().position(|b| *b == 0xFF))
            .ok_or(JpegError::Refused("no end marker"))?;
        let pos = look + found;
        match bytes.get(pos + 1) {
            Some(0x00) => look = pos + 2,
            Some(&m) if (RST0..=RST7).contains(&m) => {
                if restart == 0 || usize::from(m - RST0) != restarts % 8 {
                    return refused("a restart marker out of its order");
                }
                restarts += 1;
                if restarts > restarts_due {
                    return refused("too many restart markers");
                }
                look = pos + 2;
            }
            Some(&EOI) => break pos,
            Some(_) => return refused("a marker inside the scan"),
            None => return refused("no end marker"),
        }
    };
    if restarts != restarts_due {
        return refused("too few restart markers");
    }
    if end + 2 != bytes.len() {
        return refused("bytes after the end marker");
    }
    let scan = bytes.get(scan_at..end).unwrap_or(&[]);
    // Each block is at least two codes of one bit each.
    if scan.len() < (units * blocks * 2).div_ceil(8) {
        return refused("a scan too short for its picture");
    }
    components.shrink_to_fit();
    Ok(Parsed {
        quants,
        huffs,
        side,
        components,
        restart,
        scan,
    })
}

/// How many bytes more than a picture an encoder's file may have: the
/// segments [`clean`] leaves out (an Exif block, a colour profile).
const ENCODER_EXTRA: usize = 8_192;

fn is_jfif(body: &[u8]) -> bool {
    body.get(..5) == Some(b"JFIF\0")
}

/// A JFIF header as a picture that travels has it: 14 bytes, version 1, a
/// known unit, densities that are not 0, no thumbnail.
fn jfif_plain(body: &[u8]) -> Result<(), JpegError> {
    match body {
        &[_, _, _, _, _, 1, _, unit, xd0, xd1, yd0, yd1, 0, 0]
            if unit <= 2 && (xd0 | xd1) != 0 && (yd0 | yd1) != 0 =>
        {
            Ok(())
        }
        _ => refused("the JFIF header"),
    }
}

/// The transform byte of an Adobe APP14 segment: 0 as stored (RGB for three
/// components), 1 YCbCr, 2 YCCK.
fn adobe_transform(body: &[u8]) -> Option<u8> {
    if body.len() >= 12 && body.get(..5) == Some(b"Adobe") {
        body.get(11).copied()
    } else {
        None
    }
}

fn read_quants(body: &[u8], quants: &mut Vec<Quant>) -> Result<(), JpegError> {
    let (tables, rest) = body.as_chunks::<65>();
    if tables.is_empty() || !rest.is_empty() {
        return refused("a quantization table's length");
    }
    for table in tables {
        let id = table[0];
        if id > 3 {
            // The high half is the precision: 16 bit tables are not baseline.
            return refused("a quantization table's kind");
        }
        if quants.len() == 4 || quants.iter().any(|q| q.id == id) {
            return refused("a quantization table twice");
        }
        let mut values = [0u8; 64];
        values.copy_from_slice(&table[1..]);
        if values.contains(&0) {
            return refused("a quantization value of 0");
        }
        quants.push(Quant { id, values });
    }
    Ok(())
}

fn read_frame(body: &[u8], limits: &Limits) -> Result<(u16, Vec<Component>), JpegError> {
    let (head, rest) = match body.split_at_checked(6) {
        Some(parts) => parts,
        None => return refused("the frame's length"),
    };
    let (precision, height, width, count) = (
        head[0],
        u16::from_be_bytes([head[1], head[2]]),
        u16::from_be_bytes([head[3], head[4]]),
        usize::from(head[5]),
    );
    if precision != 8 {
        return refused("samples that are not 8 bit");
    }
    if count != 1 && count != 3 {
        return refused("the number of components");
    }
    if rest.len() != 3 * count {
        return refused("the frame's length");
    }
    if width != height {
        return refused("not square");
    }
    if width < limits.min_side || width > limits.max_side {
        return Err(JpegError::Side);
    }
    let mut components = Vec::with_capacity(count);
    for (index, entry) in rest.as_chunks::<3>().0.iter().enumerate() {
        let [id, sampling, quant] = *entry;
        let (h, v) = (sampling >> 4, sampling & 0x0F);
        // The first component may be sampled twice as finely as the others
        // (4:2:0, 4:2:2, 4:4:0, 4:4:4); nothing else is taken.
        let finest = if index == 0 && count == 3 { 2 } else { 1 };
        if h == 0 || v == 0 || h > finest || v > finest {
            return refused("a sampling factor");
        }
        if quant > 3 {
            return refused("a quantization table's number");
        }
        if components.iter().any(|other: &Component| other.id == id) {
            return refused("a component twice");
        }
        components.push(Component {
            id,
            h,
            v,
            quant,
            dc: 0,
            ac: 0,
        });
    }
    Ok((width, components))
}

fn read_huffs(body: &[u8], huffs: &mut Vec<Huff>) -> Result<(), JpegError> {
    let mut rest = body;
    if rest.is_empty() {
        return refused("a Huffman table's length");
    }
    while !rest.is_empty() {
        let (head, tail) = match rest.split_at_checked(17) {
            Some(parts) => parts,
            None => return refused("a Huffman table's length"),
        };
        let (class, id) = (head[0] >> 4, head[0] & 0x0F);
        if class > 1 || id > 1 {
            return refused("a Huffman table's kind");
        }
        if huffs.len() == 4 || huffs.iter().any(|h| h.class == class && h.id == id) {
            return refused("a Huffman table twice");
        }
        let counts = &head[1..];
        let total: usize = counts.iter().map(|n| usize::from(*n)).sum();
        // The counts make a prefix code, and no code is all ones.
        let mut space: u32 = 0;
        for (index, n) in counts.iter().enumerate() {
            space += u32::from(*n) << (15 - index);
        }
        if total == 0 || space > 0xFFFF {
            return refused("Huffman counts that make no code");
        }
        let (symbols, after) = match tail.split_at_checked(total) {
            Some(parts) => parts,
            None => return refused("a Huffman table's length"),
        };
        let mut seen = [false; 256];
        for symbol in symbols {
            let (run, size) = (symbol >> 4, symbol & 0x0F);
            let baseline = if class == 0 {
                // A DC symbol is a size, 0 to 11.
                *symbol <= 11
            } else {
                // An AC symbol is a run and a size of 1 to 10, or the end of
                // the block, or sixteen zeros.
                (1..=10).contains(&size) || (size == 0 && (run == 0 || run == 15))
            };
            if !baseline || std::mem::replace(&mut seen[usize::from(*symbol)], true) {
                return refused("a Huffman symbol");
            }
        }
        huffs.push(Huff {
            class,
            id,
            body: head[1..].iter().chain(symbols).copied().collect(),
        });
        rest = after;
    }
    Ok(())
}

/// The scan's header: every component of the frame, in the frame's order,
/// the whole spectrum in one pass.
fn read_scan_header(body: &[u8], components: &mut [Component]) -> Result<(), JpegError> {
    let count = components.len();
    if body.len() != 4 + 2 * count || usize::from(body[0]) != count {
        return refused("a scan without every component");
    }
    for (c, entry) in components.iter_mut().zip(body[1..].as_chunks::<2>().0) {
        let [id, tables] = *entry;
        let (dc, ac) = (tables >> 4, tables & 0x0F);
        if id != c.id {
            return refused("a scan without every component");
        }
        if dc > 1 || ac > 1 {
            return refused("a Huffman table's number");
        }
        c.dc = dc;
        c.ac = ac;
    }
    if body[1 + 2 * count..] != [0x00, 0x3F, 0x00] {
        return refused("a scan that is not the whole spectrum");
    }
    Ok(())
}

/// A flat square of `side` pixels, grey or in colour (4:2:0): every block
/// the same, each two codes of one bit. It is a picture [`check`] takes for
/// a side inside the limits, and a real decoder opens it. For a preview
/// where no picture library can make one (the terminal's lab commands), and
/// for tests.
pub fn flat(side: u16, colour: bool) -> Vec<u8> {
    let components: u8 = if colour { 3 } else { 1 };
    let mut out = vec![0xFF, SOI];
    out.extend_from_slice(&JFIF_APP0);
    out.extend_from_slice(&[0xFF, DQT, 0x00, 0x43, 0x00]);
    out.extend_from_slice(&[1u8; 64]);
    out.extend_from_slice(&[0xFF, SOF0, 0x00, 8 + 3 * components, 8]);
    out.extend_from_slice(&side.to_be_bytes());
    out.extend_from_slice(&side.to_be_bytes());
    out.push(components);
    for index in 0..components {
        let sampling = if colour && index == 0 { 0x22 } else { 0x11 };
        out.extend_from_slice(&[index + 1, sampling, 0]);
    }
    for class in [0u8, 1] {
        // One code of one bit: a size of 0, and the end of the block.
        out.extend_from_slice(&[0xFF, DHT, 0x00, 20, class << 4, 1]);
        out.extend_from_slice(&[0u8; 16]);
    }
    out.extend_from_slice(&[0xFF, SOS, 0x00, 6 + 2 * components, components]);
    for index in 0..components {
        out.extend_from_slice(&[index + 1, 0x00]);
    }
    out.extend_from_slice(&[0x00, 0x3F, 0x00]);
    let px = usize::from(side);
    let (units, blocks) = if colour {
        (px.div_ceil(16) * px.div_ceil(16), 6)
    } else {
        (px.div_ceil(8) * px.div_ceil(8), 1)
    };
    out.extend(std::iter::repeat_n(0u8, (units * blocks * 2).div_ceil(8)));
    out.extend_from_slice(&[0xFF, EOI]);
    out
}

#[cfg(test)]
pub(crate) mod testing {
    //! JPEGs made by hand for tests: a grey or a colour square whose every
    //! block is flat. A real decoder opens them.

    /// One Huffman table with a single code of one bit for `symbol`.
    fn huff(class: u8, id: u8, symbol: u8) -> Vec<u8> {
        let mut out = vec![0xFF, 0xC4, 0x00, 20, (class << 4) | id, 1];
        out.extend_from_slice(&[0u8; 15]);
        out.push(symbol);
        out
    }

    /// The parts of a picture, each a whole segment, so that a test can
    /// leave one out, change one or put them in another order.
    pub(crate) struct Parts {
        pub jfif: Vec<u8>,
        pub quant: Vec<u8>,
        pub frame: Vec<u8>,
        pub huffs: Vec<u8>,
        pub restart: Vec<u8>,
        pub scan_header: Vec<u8>,
        pub scan: Vec<u8>,
    }

    impl Parts {
        /// The file in the order a picture travels in.
        pub(crate) fn bytes(&self) -> Vec<u8> {
            let mut out = vec![0xFF, 0xD8];
            for part in [
                &self.jfif,
                &self.quant,
                &self.frame,
                &self.huffs,
                &self.restart,
                &self.scan_header,
                &self.scan,
            ] {
                out.extend_from_slice(part);
            }
            out.extend_from_slice(&[0xFF, 0xD9]);
            out
        }
    }

    /// A square of `side` pixels with `components` (1 or 3; colour is
    /// 4:2:0), and a restart marker after every `restart` units (0: none).
    pub(crate) fn parts(side: u16, components: u8, restart: u16) -> Parts {
        let mut quant = vec![0xFF, 0xDB, 0x00, 0x43, 0x00];
        quant.extend_from_slice(&[1u8; 64]);
        let mut frame = vec![0xFF, 0xC0, 0x00, 8 + 3 * components, 8];
        frame.extend_from_slice(&side.to_be_bytes());
        frame.extend_from_slice(&side.to_be_bytes());
        frame.push(components);
        let mut scan_header = vec![0xFF, 0xDA, 0x00, 6 + 2 * components, components];
        for index in 0..components {
            let sampling = if components == 3 && index == 0 {
                0x22
            } else {
                0x11
            };
            frame.extend_from_slice(&[index + 1, sampling, 0]);
            scan_header.extend_from_slice(&[index + 1, 0x00]);
        }
        scan_header.extend_from_slice(&[0x00, 0x3F, 0x00]);
        let mut huffs = huff(0, 0, 0x00);
        huffs.extend(huff(1, 0, 0x00));
        let px = usize::from(side);
        let (units, blocks) = if components == 3 {
            (px.div_ceil(16) * px.div_ceil(16), 6)
        } else {
            (px.div_ceil(8) * px.div_ceil(8), 1)
        };
        // Each block is two codes of one bit, both 0: a flat block.
        let mut scan = Vec::new();
        let per = if restart == 0 {
            units
        } else {
            usize::from(restart)
        };
        let mut left = units;
        let mut marker = 0u8;
        while left > 0 {
            let now = left.min(per);
            scan.extend(std::iter::repeat_n(0u8, (now * blocks * 2).div_ceil(8)));
            left -= now;
            if left > 0 {
                scan.extend_from_slice(&[0xFF, 0xD0 + marker]);
                marker = (marker + 1) % 8;
            }
        }
        let restart = if restart == 0 {
            Vec::new()
        } else {
            let mut out = vec![0xFF, 0xDD, 0x00, 0x04];
            out.extend_from_slice(&restart.to_be_bytes());
            out
        };
        Parts {
            jfif: super::JFIF_APP0.to_vec(),
            quant,
            frame,
            huffs,
            restart,
            scan_header,
            scan,
        }
    }

    /// A picture as it travels: `side` pixels, colour, no restart markers.
    pub(crate) fn picture(side: u16) -> Vec<u8> {
        parts(side, 3, 0).bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{parts, picture, Parts};
    use super::*;

    fn rule(bytes: &[u8]) -> &'static str {
        match check(bytes, &PICTURE) {
            Err(JpegError::Refused(rule)) => rule,
            other => panic!("not refused: {other:?}"),
        }
    }

    /// A segment: its marker, its length and `body`.
    fn segment(marker: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0xFF, marker];
        out.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn with(change: impl FnOnce(&mut Parts)) -> Vec<u8> {
        let mut p = parts(64, 3, 0);
        change(&mut p);
        p.bytes()
    }

    #[test]
    fn a_plain_square_is_taken_grey_and_colour_with_and_without_restarts() {
        for (side, components, restart) in [
            (64u16, 3u8, 0u16),
            (64, 1, 0),
            (384, 3, 24),
            (384, 3, 0),
            (512, 3, 7),
            (100, 3, 3),
            (100, 1, 13),
            (64, 3, 1),
            (64, 3, 16),
            (64, 3, 500),
        ] {
            let bytes = parts(side, components, restart).bytes();
            assert_eq!(
                check(&bytes, &PICTURE),
                Ok(Checked { side, components }),
                "{side} px, {components} components, restart {restart}"
            );
        }
        assert_eq!(
            check(&parts(32, 3, 0).bytes(), &PREVIEW),
            Ok(Checked {
                side: 32,
                components: 3
            })
        );
    }

    #[test]
    fn a_flat_square_is_a_picture_and_the_one_the_tests_make_by_hand() {
        for (side, colour) in [(32u16, true), (64, false), (384, true), (512, true)] {
            let components = if colour { 3 } else { 1 };
            assert_eq!(flat(side, colour), parts(side, components, 0).bytes());
        }
        assert_eq!(
            check(&flat(32, true), &PREVIEW),
            Ok(Checked {
                side: 32,
                components: 3
            })
        );
        assert_eq!(
            check(&flat(384, true), &PICTURE),
            Ok(Checked {
                side: 384,
                components: 3
            })
        );
        assert!(flat(32, true).len() <= PREVIEW.max_len);
    }

    #[test]
    fn a_side_or_a_length_outside_the_limits_is_named_as_such() {
        assert_eq!(check(&picture(48), &PICTURE), Err(JpegError::Side));
        assert_eq!(check(&picture(520), &PICTURE), Err(JpegError::Side));
        assert_eq!(
            check(&picture(64), &PREVIEW),
            Ok(Checked {
                side: 64,
                components: 3
            })
        );
        assert_eq!(check(&picture(8), &PREVIEW), Err(JpegError::Side));
        assert_eq!(check(&picture(72), &PREVIEW), Err(JpegError::Side));
        // A file one byte over the limit is not walked at all.
        let mut long = picture(64);
        long.resize(PICTURE.max_len + 1, 0);
        assert_eq!(check(&long, &PICTURE), Err(JpegError::TooLong));
        let mut p = parts(64, 3, 0);
        p.frame[5..9].copy_from_slice(&[0, 64, 0, 80]);
        assert_eq!(rule(&p.bytes()), "not square");
    }

    #[test]
    fn every_frame_but_the_baseline_one_is_refused() {
        for marker in 0xC1u8..=0xCF {
            if marker == DHT {
                continue;
            }
            let bytes = with(|p| p.frame[1] = marker);
            assert_eq!(rule(&bytes), "not a baseline frame", "{marker:#x}");
        }
        assert_eq!(
            rule(&with(|p| p.frame[4] = 12)),
            "samples that are not 8 bit"
        );
        assert_eq!(
            rule(&with(|p| p.frame[4] = 16)),
            "samples that are not 8 bit"
        );
    }

    #[test]
    fn segments_that_hold_no_pixel_are_refused_in_a_picture_that_travels() {
        for marker in 0xE1u8..=0xEF {
            let bytes = with(|p| p.jfif.extend(segment(marker, b"Exif\0\0")));
            assert_eq!(rule(&bytes), "an application segment", "{marker:#x}");
        }
        // A second JFIF header, and a JFIF extension.
        assert_eq!(
            rule(&with(|p| p.jfif.extend(JFIF_APP0))),
            "the order of the segments"
        );
        assert_eq!(
            rule(&with(|p| p.jfif.extend(segment(APP0, b"JFXX\0\x10")))),
            "an application segment"
        );
        assert_eq!(
            rule(&with(|p| p.jfif.extend(segment(COM, b"hello")))),
            "a comment"
        );
        for marker in [0x01u8, 0xDC, 0xDE, 0xDF, 0xF0, 0xF7, 0xFD, 0x02, 0xBF] {
            let bytes = with(|p| p.quant.extend(segment(marker, &[0, 0])));
            assert_eq!(
                rule(&bytes),
                "a marker this picture may not have",
                "{marker:#x}"
            );
        }
        // A JFIF header with a thumbnail, with a density of 0, of version 2.
        let mut thumb = JFIF_APP0.to_vec();
        thumb[3] = 0x13;
        thumb[16] = 1;
        thumb[17] = 1;
        thumb.extend_from_slice(&[9, 9, 9]);
        assert_eq!(rule(&with(|p| p.jfif = thumb)), "the JFIF header");
        assert_eq!(rule(&with(|p| p.jfif[13] = 0)), "the JFIF header");
        assert_eq!(rule(&with(|p| p.jfif[9] = 2)), "the JFIF header");
        assert_eq!(rule(&with(|p| p.jfif.clear())), "no JFIF header");
    }

    #[test]
    fn the_segments_come_in_the_one_order() {
        let p = parts(64, 3, 4);
        let order = |list: [&Vec<u8>; 6]| {
            let mut out = vec![0xFF, 0xD8];
            for part in list {
                out.extend_from_slice(part);
            }
            out.extend_from_slice(&p.scan);
            out.extend_from_slice(&[0xFF, 0xD9]);
            out
        };
        let right = order([
            &p.jfif,
            &p.quant,
            &p.frame,
            &p.huffs,
            &p.restart,
            &p.scan_header,
        ]);
        assert!(check(&right, &PICTURE).is_ok());
        for wrong in [
            order([
                &p.quant,
                &p.jfif,
                &p.frame,
                &p.huffs,
                &p.restart,
                &p.scan_header,
            ]),
            order([
                &p.jfif,
                &p.frame,
                &p.quant,
                &p.huffs,
                &p.restart,
                &p.scan_header,
            ]),
            order([
                &p.jfif,
                &p.quant,
                &p.huffs,
                &p.frame,
                &p.restart,
                &p.scan_header,
            ]),
            order([
                &p.jfif,
                &p.quant,
                &p.frame,
                &p.restart,
                &p.huffs,
                &p.scan_header,
            ]),
            order([
                &p.jfif,
                &p.huffs,
                &p.quant,
                &p.frame,
                &p.restart,
                &p.scan_header,
            ]),
        ] {
            assert!(
                matches!(check(&wrong, &PICTURE), Err(JpegError::Refused(_))),
                "an order that is not the one order"
            );
        }
    }

    #[test]
    fn tables_are_8_bit_whole_and_never_twice() {
        assert_eq!(
            rule(&with(|p| p.quant[4] = 0x10)),
            "a quantization table's kind"
        );
        assert_eq!(
            rule(&with(|p| p.quant[4] = 0x04)),
            "a quantization table's kind"
        );
        assert_eq!(
            rule(&with(|p| p.quant[20] = 0)),
            "a quantization value of 0"
        );
        assert_eq!(
            rule(&with(|p| {
                let again = p.quant.clone();
                p.quant.extend(again);
            })),
            "a quantization table twice"
        );
        assert_eq!(
            rule(&with(|p| {
                p.quant.pop();
                p.quant[3] = 0x42;
            })),
            "a quantization table's length"
        );
        // A component that names a table the file does not have.
        assert_eq!(
            rule(&with(|p| p.frame[12] = 1)),
            "a quantization table is missing"
        );
        assert_eq!(
            rule(&with(|p| p.frame[12] = 4)),
            "a quantization table's number"
        );
        // Five tables.
        let five = with(|p| {
            p.quant.clear();
            for id in [0u8, 1, 2, 3, 3] {
                let mut body = vec![id];
                body.extend_from_slice(&[1u8; 64]);
                p.quant.extend(segment(DQT, &body));
            }
        });
        assert_eq!(rule(&five), "a quantization table twice");
    }

    #[test]
    fn huffman_tables_make_a_code_of_baseline_symbols() {
        assert_eq!(rule(&with(|p| p.huffs[4] = 0x20)), "a Huffman table's kind");
        assert_eq!(rule(&with(|p| p.huffs[4] = 0x02)), "a Huffman table's kind");
        // Three codes of one bit.
        assert_eq!(
            rule(&with(|p| {
                p.huffs[5] = 3;
                p.huffs[3] = 22;
                p.huffs.splice(21..21, [1u8, 2]);
            })),
            "Huffman counts that make no code"
        );
        // Two codes of one bit: the second is all ones.
        assert_eq!(
            rule(&with(|p| {
                p.huffs[5] = 2;
                p.huffs[3] = 21;
                p.huffs.insert(21, 1);
            })),
            "Huffman counts that make no code"
        );
        // No code at all.
        assert_eq!(
            rule(&with(|p| {
                p.huffs[5] = 0;
                p.huffs[3] = 19;
                p.huffs.remove(21);
            })),
            "Huffman counts that make no code"
        );
        // A DC size of 12; an AC size of 11; an AC run with size 0.
        assert_eq!(rule(&with(|p| p.huffs[21] = 12)), "a Huffman symbol");
        assert_eq!(rule(&with(|p| p.huffs[43] = 0x0B)), "a Huffman symbol");
        assert_eq!(rule(&with(|p| p.huffs[43] = 0x30)), "a Huffman symbol");
        // A count that runs past the segment.
        assert_eq!(rule(&with(|p| p.huffs[20] = 5)), "a Huffman table's length");
        // The same table twice, and a table a component names that is not there.
        assert_eq!(
            rule(&with(|p| {
                let again = p.huffs[..22].to_vec();
                p.huffs.extend(again);
            })),
            "a Huffman table twice"
        );
        assert_eq!(
            rule(&with(|p| p.scan_header[6] = 0x10)),
            "a Huffman table is missing"
        );
        assert_eq!(
            rule(&with(|p| p.scan_header[6] = 0x02)),
            "a Huffman table's number"
        );
        // The same symbol twice in one table.
        let mut body = vec![0x10u8, 0, 2];
        body.extend_from_slice(&[0u8; 14]);
        body.extend_from_slice(&[0x11, 0x11]);
        assert_eq!(
            rule(&with(|p| {
                p.huffs.truncate(22);
                p.huffs.extend(segment(DHT, &body));
            })),
            "a Huffman symbol"
        );
    }

    #[test]
    fn the_frame_has_one_or_three_components_sampled_as_a_picture_is() {
        assert_eq!(rule(&with(|p| p.frame[9] = 4)), "the number of components");
        assert_eq!(rule(&with(|p| p.frame[9] = 2)), "the number of components");
        assert_eq!(rule(&with(|p| p.frame[3] = 16)), "the frame's length");
        // The second component sampled finer than 1, the first finer than 2,
        // a factor of 0.
        assert_eq!(rule(&with(|p| p.frame[14] = 0x21)), "a sampling factor");
        assert_eq!(rule(&with(|p| p.frame[11] = 0x41)), "a sampling factor");
        assert_eq!(rule(&with(|p| p.frame[11] = 0x02)), "a sampling factor");
        assert_eq!(rule(&with(|p| p.frame[13] = 1)), "a component twice");
        // Grey is sampled once.
        let mut grey = parts(64, 1, 0);
        grey.frame[11] = 0x22;
        assert_eq!(rule(&grey.bytes()), "a sampling factor");
        // 4:2:2, 4:4:0 and 4:4:4 are pictures too.
        for sampling in [0x21u8, 0x12, 0x11] {
            let mut p = parts(64, 3, 0);
            p.frame[11] = sampling;
            let (h, v) = (usize::from(sampling >> 4), usize::from(sampling & 15));
            let units = 64usize.div_ceil(8 * h) * 64usize.div_ceil(8 * v);
            p.scan = vec![0u8; (units * (h * v + 2) * 2).div_ceil(8)];
            assert!(check(&p.bytes(), &PICTURE).is_ok(), "{sampling:#x}");
        }
    }

    #[test]
    fn there_is_one_scan_with_every_component_and_the_whole_spectrum() {
        assert_eq!(
            rule(&with(|p| {
                p.scan_header[3] = 8;
                p.scan_header[4] = 1;
                p.scan_header.drain(7..11);
            })),
            "a scan without every component"
        );
        assert_eq!(
            rule(&with(|p| p.scan_header[5] = 3)),
            "a scan without every component"
        );
        assert_eq!(
            rule(&with(|p| p.scan_header[11] = 1)),
            "a scan that is not the whole spectrum"
        );
        assert_eq!(
            rule(&with(|p| p.scan_header[12] = 5)),
            "a scan that is not the whole spectrum"
        );
        assert_eq!(
            rule(&with(|p| p.scan_header[13] = 0x10)),
            "a scan that is not the whole spectrum"
        );
        // A second scan: its marker lies inside the first one's data.
        assert_eq!(
            rule(&with(|p| {
                let again = p.scan_header.clone();
                p.scan.extend(again);
                p.scan.extend_from_slice(&[0u8; 24]);
            })),
            "a marker inside the scan"
        );
        assert_eq!(
            rule(&with(|p| p.frame.clear())),
            "the order of the segments"
        );
        assert_eq!(
            rule(&with(|p| {
                let again = p.frame.clone();
                p.frame.extend(again);
            })),
            "two frames"
        );
    }

    #[test]
    fn inside_the_scan_only_data_stuffed_bytes_and_restart_markers_in_order() {
        // A stuffed byte is data.
        assert!(check(
            &with(|p| p.scan.extend_from_slice(&[0xFF, 0x00, 0x12])),
            &PICTURE
        )
        .is_ok());
        for marker in [0xC0u8, 0xC4, 0xD8, 0xDB, 0xDC, 0xE1, 0xFE, 0xFF, 0x01] {
            let bytes = with(|p| p.scan.extend_from_slice(&[0xFF, marker, 0, 2]));
            assert_eq!(rule(&bytes), "a marker inside the scan", "{marker:#x}");
        }
        // A restart marker with no interval declared.
        assert_eq!(
            rule(&with(|p| p.scan.extend_from_slice(&[0xFF, 0xD0, 0]))),
            "a restart marker out of its order"
        );
        // With an interval: the markers count up from 0 and wrap after 7.
        let good = parts(64, 3, 1);
        assert!(check(&good.bytes(), &PICTURE).is_ok());
        let first = good.scan.iter().position(|b| *b == 0xFF).unwrap();
        let mut wrong = parts(64, 3, 1);
        wrong.scan[first + 1] = 0xD1;
        assert_eq!(rule(&wrong.bytes()), "a restart marker out of its order");
        let mut few = parts(64, 3, 1);
        few.scan.drain(first..first + 2);
        assert_eq!(rule(&few.bytes()), "a restart marker out of its order");
        let mut last = parts(64, 3, 1);
        let end = last.scan.len();
        last.scan.truncate(end - 4);
        assert_eq!(rule(&last.bytes()), "too few restart markers");
        let mut many = parts(64, 3, 16);
        many.scan.extend_from_slice(&[0xFF, 0xD0, 0, 0]);
        assert_eq!(rule(&many.bytes()), "too many restart markers");
        assert_eq!(
            rule(&with(|p| p.restart = vec![0xFF, DRI, 0, 4, 0, 0])),
            "a restart interval of 0"
        );
        assert_eq!(
            rule(&with(
                |p| p.restart = vec![0xFF, DRI, 0, 4, 0, 9, 0xFF, DRI, 0, 4, 0, 9]
            )),
            "two restart intervals"
        );
        assert_eq!(
            rule(&with(|p| p.restart = vec![0xFF, DRI, 0, 5, 0, 9, 0])),
            "the restart interval's length"
        );
    }

    #[test]
    fn the_file_ends_with_its_end_marker_and_holds_a_scan_long_enough() {
        let whole = picture(64);
        let mut after = whole.clone();
        after.push(0);
        assert_eq!(rule(&after), "bytes after the end marker");
        let mut twice = whole.clone();
        twice.extend_from_slice(&whole);
        assert_eq!(rule(&twice), "bytes after the end marker");
        // Every cut of the file is refused, and none reads past the end.
        for cut in 0..whole.len() {
            assert!(
                matches!(check(&whole[..cut], &PICTURE), Err(JpegError::Refused(_))),
                "cut at {cut}"
            );
        }
        assert_eq!(
            rule(&with(|p| p.scan.truncate(3))),
            "a scan too short for its picture"
        );
        assert_eq!(rule(&[]), "no start marker");
        assert_eq!(rule(b"\x89PNG\r\n\x1a\n"), "no start marker");
        assert_eq!(rule(b"GIF89a"), "no start marker");
        assert_eq!(rule(b"%PDF-1.7"), "no start marker");
        // A segment whose length says less than its own two bytes.
        assert_eq!(rule(&with(|p| p.quant[3] = 1)), "a segment's length");
    }

    #[test]
    fn no_single_changed_byte_makes_the_walk_read_outside_or_panic() {
        let whole = parts(64, 3, 4).bytes();
        for at in 0..whole.len() {
            for value in [0x00u8, 0x01, 0x7F, 0xC4, 0xD9, 0xDA, 0xFF] {
                let mut bytes = whole.clone();
                bytes[at] = value;
                let _ = check(&bytes, &PICTURE);
                let _ = clean(&bytes, &PICTURE);
            }
        }
    }

    /// What an encoder writes: the frame first, then the Huffman tables, the
    /// quantization tables, a restart interval, with an Exif block and other
    /// segments around them.
    fn from_an_encoder(p: &Parts) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8];
        out.extend_from_slice(&[0xFF, APP0, 0, 16]);
        out.extend_from_slice(b"JFIF\0\x01\x01\x01\x00\x48\x00\x48\x00\x00");
        out.extend(segment(0xE1, b"Exif\0\0MM\0*\0\0\0\x08"));
        out.extend(segment(0xED, b"Photoshop 3.0\08BIM"));
        out.extend(segment(0xE2, b"ICC_PROFILE\0\x01\x01"));
        out.extend_from_slice(&p.frame);
        out.extend(segment(COM, b"made by an encoder"));
        out.extend_from_slice(&p.huffs);
        out.extend_from_slice(&p.quant);
        out.extend_from_slice(&p.restart);
        out.extend_from_slice(&p.scan_header);
        out.extend_from_slice(&p.scan);
        out.extend_from_slice(&[0xFF, 0xD9]);
        out
    }

    #[test]
    fn clean_writes_an_encoders_file_in_the_one_order_without_what_holds_no_pixel() {
        for (side, components, restart) in [(384u16, 3u8, 24u16), (64, 1, 0), (100, 3, 0)] {
            let p = parts(side, components, restart);
            let raw = from_an_encoder(&p);
            assert!(
                check(&raw, &PICTURE).is_err(),
                "an encoder's file does not travel as it is"
            );
            let cleaned = clean(&raw, &PICTURE).unwrap();
            // Byte for byte the picture made by hand in the one order.
            assert_eq!(cleaned, p.bytes());
            assert_eq!(check(&cleaned, &PICTURE), Ok(Checked { side, components }));
            // Cleaning what is clean changes nothing.
            assert_eq!(clean(&cleaned, &PICTURE).unwrap(), cleaned);
            for word in [&b"Exif"[..], b"Photoshop", b"ICC_PROFILE", b"made by"] {
                assert!(!cleaned.windows(word.len()).any(|w| w == word));
            }
        }
    }

    #[test]
    fn clean_sorts_tables_and_takes_fill_bytes_and_drops_an_interval_of_0() {
        let mut p = parts(64, 3, 0);
        // Two quantization tables in one segment, the higher number first;
        // the Huffman tables AC first.
        let mut body = vec![1u8];
        body.extend_from_slice(&[2u8; 64]);
        body.push(0);
        body.extend_from_slice(&[1u8; 64]);
        p.quant = segment(DQT, &body);
        p.frame[15] = 1;
        p.frame[18] = 1;
        let (dc, ac) = (p.huffs[..22].to_vec(), p.huffs[22..].to_vec());
        p.huffs = [ac, dc].concat();
        p.restart = vec![0xFF, 0xFF, 0xFF, DRI, 0, 4, 0, 0];
        let raw = from_an_encoder(&p);
        let cleaned = clean(&raw, &PICTURE).unwrap();
        assert!(check(&cleaned, &PICTURE).is_ok());
        let ids: Vec<u8> = cleaned
            .windows(2)
            .enumerate()
            .filter(|(_, w)| *w == [0xFF, DQT])
            .map(|(at, _)| cleaned[at + 4])
            .collect();
        assert_eq!(
            ids,
            vec![0, 1],
            "one table a segment, the lower number first"
        );
        assert!(!cleaned.windows(2).any(|w| w == [0xFF, DRI]));
        let first_huff = cleaned.windows(2).position(|w| w == [0xFF, DHT]).unwrap();
        assert_eq!(cleaned[first_huff + 4], 0x00, "the DC table comes first");
    }

    #[test]
    fn clean_refuses_colours_that_are_not_ycbcr_and_what_check_refuses() {
        let p = parts(64, 3, 0);
        let adobe = |transform: u8| {
            let mut body = b"Adobe\0\x64\0\0\0\0".to_vec();
            body.push(transform);
            segment(APP14, &body)
        };
        let with_adobe = |transform: u8| {
            let mut q = parts(64, 3, 0);
            q.jfif.extend(adobe(transform));
            q.bytes()
        };
        assert_eq!(
            clean(&with_adobe(0), &PICTURE),
            Err(JpegError::Refused("colours that are not YCbCr"))
        );
        assert_eq!(
            clean(&with_adobe(2), &PICTURE),
            Err(JpegError::Refused("colours that are not YCbCr"))
        );
        assert_eq!(clean(&with_adobe(1), &PICTURE).unwrap(), p.bytes());
        // Three components named R, G and B with no JFIF header.
        let mut rgb = parts(64, 3, 0);
        rgb.jfif.clear();
        for (at, name) in [(10usize, b'R'), (13, b'G'), (16, b'B')] {
            rgb.frame[at] = name;
        }
        for (at, name) in [(5usize, b'R'), (7, b'G'), (9, b'B')] {
            rgb.scan_header[at] = name;
        }
        assert_eq!(
            clean(&rgb.bytes(), &PICTURE),
            Err(JpegError::Refused("colours that are not YCbCr"))
        );
        // Grey has no colours to change.
        let mut grey = parts(64, 1, 0);
        grey.jfif = adobe(0);
        assert!(clean(&grey.bytes(), &PICTURE).is_ok());
        // What no rewrite makes right.
        let mut progressive = parts(64, 3, 0);
        progressive.frame[1] = 0xC2;
        assert_eq!(
            clean(&from_an_encoder(&progressive), &PICTURE),
            Err(JpegError::Refused("not a baseline frame"))
        );
        let mut after = from_an_encoder(&p);
        after.extend_from_slice(b"more");
        assert_eq!(
            clean(&after, &PICTURE),
            Err(JpegError::Refused("bytes after the end marker"))
        );
        assert_eq!(clean(&picture(520), &PICTURE), Err(JpegError::Side));
        // An encoder's file may be a little longer than a picture; what comes
        // out may not.
        let mut long = parts(64, 3, 0);
        long.scan.resize(PICTURE.max_len - 200, 0);
        let raw = from_an_encoder(&long);
        assert!(raw.len() > PICTURE.max_len);
        assert!(clean(&raw, &PICTURE).is_ok());
        long.scan.resize(PICTURE.max_len, 0);
        assert_eq!(
            clean(&from_an_encoder(&long), &PICTURE),
            Err(JpegError::TooLong)
        );
        let mut far = parts(64, 3, 0);
        far.scan.resize(PICTURE.max_len + ENCODER_EXTRA, 0);
        assert_eq!(
            clean(&from_an_encoder(&far), &PICTURE),
            Err(JpegError::TooLong)
        );
    }
}
