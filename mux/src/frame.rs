use thiserror::Error;

/// Frame flags.
pub const FLAG_FIRST: u16 = 1 << 0; // first frame in stream
pub const FLAG_LAST: u16 = 1 << 1; // stream is being closed gracefully
pub const FLAG_ERROR: u16 = 1 << 2; // stream is being closed due to an error

/// Reserved stream IDs.
pub const ID_KEEPALIVE: u32 = 0; // empty frame to keep connection open
pub const ID_LOWEST_STREAM: u32 = 1 << 8; // IDs below this value are reserved

/// AEAD constants.
pub const AEAD_NONCE_SIZE: usize = 12;
pub const AEAD_TAG_SIZE: usize = 16;

/// Size of a frame header on the wire: 4 (id) + 2 (length) + 2 (flags).
pub const FRAME_HEADER_SIZE: usize = 4 + 2 + 2;

#[derive(Debug, Error)]
pub enum FrameHeaderError {
    #[error("buffer too short for frame header")]
    BufferTooShort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub id: u32,
    pub length: u16,
    pub flags: u16,
}

/// Encodes the header as an 8-byte little-endian array.
///
/// The ID is shifted left by 1 with the lowest bit set to 1, which
/// distinguishes frame data from padding (see the spec's "Covert Frames"
/// section).
impl From<FrameHeader> for [u8; FRAME_HEADER_SIZE] {
    fn from(h: FrameHeader) -> Self {
        let mut buf = [0u8; FRAME_HEADER_SIZE];
        let id_wire = (h.id << 1) | 1;
        buf[0..4].copy_from_slice(&id_wire.to_le_bytes());
        buf[4..6].copy_from_slice(&h.length.to_le_bytes());
        buf[6..8].copy_from_slice(&h.flags.to_le_bytes());
        buf
    }
}

/// Decodes a header from a byte slice that must be at least [`FRAME_HEADER_SIZE`] bytes.
impl TryFrom<&[u8]> for FrameHeader {
    type Error = FrameHeaderError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < FRAME_HEADER_SIZE {
            return Err(FrameHeaderError::BufferTooShort);
        }
        let id_wire = u32::from_le_bytes(buf[0..4].try_into().expect("slice length checked above"));
        Ok(Self {
            id: id_wire >> 1,
            length: u16::from_le_bytes(buf[4..6].try_into().expect("slice length checked above")),
            flags: u16::from_le_bytes(buf[6..8].try_into().expect("slice length checked above")),
        })
    }
}

/// Appends a complete frame (header + payload) to `buf`.
pub fn append_frame(buf: &mut Vec<u8>, h: FrameHeader, payload: &[u8]) {
    let header_bytes: [u8; FRAME_HEADER_SIZE] = h.into();
    buf.extend_from_slice(&header_bytes);
    buf.extend_from_slice(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_roundtrip_header() {
        let h = FrameHeader {
            id: 256,
            length: 1024,
            flags: FLAG_FIRST,
        };
        let buf: [u8; FRAME_HEADER_SIZE] = h.into();

        // verify the wire-encoded ID has the lowest bit set
        let id_wire = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(id_wire & 1, 1);
        assert_eq!(id_wire >> 1, 256);

        let decoded = FrameHeader::try_from(buf.as_slice()).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn frame_header_roundtrip_keepalive() {
        let h = FrameHeader {
            id: ID_KEEPALIVE,
            length: 0,
            flags: 0,
        };
        let buf: [u8; FRAME_HEADER_SIZE] = h.into();

        let id_wire = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(id_wire, 1); // (0 << 1) | 1

        let decoded = FrameHeader::try_from(buf.as_slice()).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn frame_header_decode_too_short() {
        let buf = [0u8; 4];
        let result = FrameHeader::try_from(buf.as_slice());
        assert!(matches!(result, Err(FrameHeaderError::BufferTooShort)));
    }

    #[test]
    fn append_frame_builds_correct_bytes() {
        let h = FrameHeader {
            id: 300,
            length: 5,
            flags: FLAG_LAST | FLAG_ERROR,
        };
        let payload = b"hello";

        let mut buf = Vec::new();
        append_frame(&mut buf, h, payload);

        assert_eq!(buf.len(), FRAME_HEADER_SIZE + payload.len());

        let decoded = FrameHeader::try_from(buf.as_slice()).unwrap();
        assert_eq!(decoded.id, 300);
        assert_eq!(decoded.length, 5);
        assert_ne!(decoded.flags & FLAG_LAST, 0);
        assert_ne!(decoded.flags & FLAG_ERROR, 0);
        assert_eq!(decoded.flags & FLAG_FIRST, 0);
        assert_eq!(&buf[FRAME_HEADER_SIZE..], b"hello");
    }
}
