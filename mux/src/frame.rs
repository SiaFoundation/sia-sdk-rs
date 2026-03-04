use std::io;
use std::ops::Range;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

#[derive(Debug, Error)]
pub(crate) enum PacketReaderError {
    #[error("could not read frame header: {0}")]
    ReadHeader(io::Error),
    #[error("could not read frame payload: {0}")]
    ReadPayload(io::Error),
    #[error("peer sent too-large frame ({0} bytes)")]
    FrameTooLarge(u16),
    #[error("buffer too small ({0} bytes, need at least {FRAME_HEADER_SIZE})")]
    BufferTooSmall(usize),
    #[error("invalid frame header: {0}")]
    InvalidHeader(#[from] FrameHeaderError),
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

/// Trait for sequential packet encryption/decryption.
pub(crate) trait PacketCipher {
    /// Decrypts `buf` in place, returning the length of the plaintext.
    /// The plaintext occupies `buf[..len]` after decryption.
    fn decrypt_in_place(&mut self, buf: &mut [u8]) -> Result<usize, io::Error>;

    /// Encrypts `buf[..buf.len() - AEAD_TAG_SIZE]` in place, writing the
    /// authentication tag into the remaining bytes. Infallible because AEAD
    /// encryption cannot fail.
    fn encrypt_in_place(&mut self, buf: &mut [u8]);
}

pub(crate) struct PacketWriter<W, C> {
    writer: W,
    cipher: C,
    packet_size: usize,
    buf: Vec<u8>,
}

impl<W: AsyncWrite + Unpin, C: PacketCipher> PacketWriter<W, C> {
    pub fn new(writer: W, cipher: C, packet_size: usize) -> Self {
        Self {
            writer,
            cipher,
            packet_size,
            buf: vec![0u8; packet_size * 10],
        }
    }

    /// Encrypts `plaintext` into packets and writes them to the underlying
    /// writer. The caller must ensure `plaintext.len()` is a multiple of
    /// `max_frame_size` (`packet_size - AEAD_TAG_SIZE`).
    pub async fn write_encrypted(&mut self, plaintext: &[u8]) -> Result<(), io::Error> {
        let max_frame_size = self.packet_size - AEAD_TAG_SIZE;
        let num_packets = plaintext.len() / max_frame_size;
        for i in 0..num_packets {
            let packet = &mut self.buf[i * self.packet_size..][..self.packet_size];
            packet[..max_frame_size]
                .copy_from_slice(&plaintext[i * max_frame_size..][..max_frame_size]);
            self.cipher.encrypt_in_place(packet);
        }
        self.writer
            .write_all(&self.buf[..num_packets * self.packet_size])
            .await
    }
}

pub(crate) struct PacketReader<R, C> {
    reader: R,
    cipher: C,
    packet_size: usize,
    buf: Vec<u8>,
    decrypted: Range<usize>, // region of buf containing decrypted plaintext to consume
    encrypted: Range<usize>, // region of buf containing encrypted packets to decrypt
}

impl<R: AsyncRead + Unpin, C: PacketCipher> PacketReader<R, C> {
    pub fn new(reader: R, cipher: C, packet_size: usize) -> Self {
        Self {
            reader,
            cipher,
            packet_size,
            buf: vec![0u8; packet_size * 10],
            decrypted: 0..0,
            encrypted: 0..0,
        }
    }

    /// Skips any padding remaining in the current decrypted packet.
    ///
    /// Frame IDs are encoded as `(id << 1) | 1`, so bit 0 of a frame header
    /// is always 1. Padding is zero-filled, so bit 0 is 0. Checking the
    /// first bit of the next byte tells us whether we're at a frame or
    /// padding — if padding, discard the rest of the packet.
    pub fn skip_padding(&mut self) {
        // Indexing is safe: decrypted ranges are only set in read(), which
        // derives them from valid buffer positions.
        if self.decrypted.is_empty() || self.buf[self.decrypted.start] & 1 != 0 {
            return;
        }
        self.decrypted = self.decrypted.end..self.decrypted.end;
    }

    /// Reads the next frame from the stream into `buf`. Returns the decoded
    /// header and a slice of `buf` containing the payload.
    pub async fn next_frame<'a>(
        &mut self,
        buf: &'a mut [u8],
    ) -> Result<(FrameHeader, &'a [u8]), PacketReaderError> {
        self.skip_padding();

        if buf.len() < FRAME_HEADER_SIZE {
            return Err(PacketReaderError::BufferTooSmall(buf.len()));
        }

        // Read and decode header
        self.read_exact(&mut buf[..FRAME_HEADER_SIZE])
            .await
            .map_err(PacketReaderError::ReadHeader)?;

        let h = FrameHeader::try_from(&buf[..FRAME_HEADER_SIZE])?;

        let max_payload = self.packet_size - FRAME_HEADER_SIZE;
        if h.length as usize > max_payload {
            return Err(PacketReaderError::FrameTooLarge(h.length));
        }

        // Read payload into the same buffer (overwrites header bytes)
        let payload_len = h.length as usize;
        self.read_exact(&mut buf[..payload_len])
            .await
            .map_err(PacketReaderError::ReadPayload)?;

        Ok((h, &buf[..payload_len]))
    }

    /// Reads from the decrypted stream until `buf` is completely filled.
    async fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<(), io::Error> {
        while !buf.is_empty() {
            let n = self.read(buf).await?;
            buf = &mut buf[n..];
        }
        Ok(())
    }

    /// Reads decrypted data into `p`. Reads and decrypts packets from the
    /// underlying reader as needed.
    pub async fn read(&mut self, p: &mut [u8]) -> Result<usize, io::Error> {
        // if we have decrypted data, use that; otherwise, if we have an encrypted
        // packet, decrypt it and use that; otherwise, read at least one more packet,
        // decrypt it, and use that

        if self.decrypted.is_empty() {
            if self.encrypted.len() < self.packet_size {
                // Compact remaining encrypted data to the start of the buffer
                let remaining = self.encrypted.len();
                self.buf.copy_within(self.encrypted.clone(), 0);
                self.encrypted = 0..remaining;

                // Read at least enough to complete one packet
                let needed = self.packet_size - remaining;
                let mut filled = remaining;
                while filled - remaining < needed {
                    let n = self.reader.read(&mut self.buf[filled..]).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected EOF reading packet",
                        ));
                    }
                    filled += n;
                }
                self.encrypted = 0..filled;
            }

            // Decrypt the first available packet
            let packet_start = self.encrypted.start;
            let packet_end = packet_start + self.packet_size;
            let plaintext_len = self
                .cipher
                .decrypt_in_place(&mut self.buf[packet_start..packet_end])?;
            self.decrypted = packet_start..packet_start + plaintext_len;
            self.encrypted.start = packet_end;
        }

        let n = p.len().min(self.decrypted.len());
        p[..n].copy_from_slice(&self.buf[self.decrypted.start..self.decrypted.start + n]);
        self.decrypted.start += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// XOR cipher for testing PacketWriter/PacketReader round-trips.
    struct TestCipher {
        key: u8,
    }

    impl PacketCipher for TestCipher {
        fn decrypt_in_place(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
            let pt_len = buf.len() - AEAD_TAG_SIZE;
            for b in &mut buf[..pt_len] {
                *b ^= self.key;
            }
            Ok(pt_len)
        }

        fn encrypt_in_place(&mut self, buf: &mut [u8]) {
            let pt_len = buf.len() - AEAD_TAG_SIZE;
            for b in &mut buf[..pt_len] {
                *b ^= self.key;
            }
            buf[pt_len..].fill(0xFF);
        }
    }

    // Verifies that encoding and decoding a FrameHeader preserves all fields.
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

    // Verifies that the keepalive stream ID (0) round-trips correctly.
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

    // Verifies that decoding a too-short buffer returns an error.
    #[test]
    fn frame_header_decode_too_short() {
        let buf = [0u8; 4];
        let result = FrameHeader::try_from(buf.as_slice());
        assert!(matches!(result, Err(FrameHeaderError::BufferTooShort)));
    }

    // Verifies that append_frame produces a valid header followed by the payload.
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

    // Verifies that a single packet encrypted by PacketWriter can be decrypted by PacketReader.
    #[tokio::test]
    async fn packet_writer_reader_single_packet() {
        const PACKET_SIZE: usize = 64;
        const MAX_FRAME: usize = PACKET_SIZE - AEAD_TAG_SIZE;

        let (w, r) = tokio::io::duplex(65536);
        let mut writer = PacketWriter::new(w, TestCipher { key: 0xAA }, PACKET_SIZE);
        let mut reader = PacketReader::new(r, TestCipher { key: 0xAA }, PACKET_SIZE);

        let mut plaintext = vec![0u8; MAX_FRAME];
        plaintext[..13].copy_from_slice(b"hello, world!");

        writer.write_encrypted(&plaintext).await.unwrap();
        drop(writer);

        let mut buf = vec![0u8; MAX_FRAME];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, MAX_FRAME);
        assert_eq!(&buf[..13], b"hello, world!");
        assert_eq!(&buf[13..], &vec![0u8; MAX_FRAME - 13]);
    }

    // Verifies that patterned data spanning multiple packets survives the encrypt/decrypt round-trip.
    #[tokio::test]
    async fn packet_writer_reader_multiple_packets() {
        const PACKET_SIZE: usize = 64;
        const MAX_FRAME: usize = PACKET_SIZE - AEAD_TAG_SIZE;
        const NUM_PACKETS: usize = 5;

        let (w, r) = tokio::io::duplex(65536);
        let mut writer = PacketWriter::new(w, TestCipher { key: 0xDD }, PACKET_SIZE);
        let mut reader = PacketReader::new(r, TestCipher { key: 0xDD }, PACKET_SIZE);

        let mut plaintext = vec![0u8; MAX_FRAME * NUM_PACKETS];
        for (i, b) in plaintext.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        writer.write_encrypted(&plaintext).await.unwrap();
        drop(writer);

        let mut result = vec![0u8; plaintext.len()];
        let mut total = 0;
        while total < result.len() {
            let n = reader.read(&mut result[total..]).await.unwrap();
            assert!(n > 0, "read returned 0 before all data consumed");
            total += n;
        }
        assert_eq!(result, plaintext);
    }

    // Verifies that a full frame (header + payload + padding) can be written and read back via next_frame.
    #[tokio::test]
    async fn packet_writer_reader_frame_roundtrip() {
        const PACKET_SIZE: usize = 128;
        const MAX_FRAME: usize = PACKET_SIZE - AEAD_TAG_SIZE;

        let (w, r) = tokio::io::duplex(65536);
        let mut writer = PacketWriter::new(w, TestCipher { key: 0xBB }, PACKET_SIZE);
        let mut reader = PacketReader::new(r, TestCipher { key: 0xBB }, PACKET_SIZE);

        // Build a frame: header + payload, padded to packet plaintext size
        let header = FrameHeader {
            id: 300,
            length: 5,
            flags: FLAG_FIRST,
        };
        let header_bytes: [u8; FRAME_HEADER_SIZE] = header.into();

        let mut plaintext = vec![0u8; MAX_FRAME];
        plaintext[..FRAME_HEADER_SIZE].copy_from_slice(&header_bytes);
        plaintext[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + 5].copy_from_slice(b"hello");

        writer.write_encrypted(&plaintext).await.unwrap();
        drop(writer);

        let mut buf = vec![0u8; MAX_FRAME];
        let (h, payload) = reader.next_frame(&mut buf).await.unwrap();
        assert_eq!(h.id, 300);
        assert_eq!(h.length, 5);
        assert_eq!(h.flags, FLAG_FIRST);
        assert_eq!(payload, b"hello");
    }

    // Verifies that multiple frames across separate packets are read in order with correct padding skips.
    #[tokio::test]
    async fn packet_writer_reader_multiple_frames() {
        const PACKET_SIZE: usize = 128;
        const MAX_FRAME: usize = PACKET_SIZE - AEAD_TAG_SIZE;

        let (w, r) = tokio::io::duplex(65536);
        let mut writer = PacketWriter::new(w, TestCipher { key: 0xCC }, PACKET_SIZE);
        let mut reader = PacketReader::new(r, TestCipher { key: 0xCC }, PACKET_SIZE);

        let h1 = FrameHeader {
            id: 256,
            length: 3,
            flags: FLAG_FIRST,
        };
        let h2 = FrameHeader {
            id: 257,
            length: 6,
            flags: FLAG_LAST,
        };

        // Two frames, each in its own packet
        let mut plaintext = vec![0u8; MAX_FRAME * 2];

        let h1_bytes: [u8; FRAME_HEADER_SIZE] = h1.into();
        plaintext[..FRAME_HEADER_SIZE].copy_from_slice(&h1_bytes);
        plaintext[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + 3].copy_from_slice(b"foo");

        let h2_bytes: [u8; FRAME_HEADER_SIZE] = h2.into();
        plaintext[MAX_FRAME..MAX_FRAME + FRAME_HEADER_SIZE].copy_from_slice(&h2_bytes);
        plaintext[MAX_FRAME + FRAME_HEADER_SIZE..MAX_FRAME + FRAME_HEADER_SIZE + 6]
            .copy_from_slice(b"barbaz");

        writer.write_encrypted(&plaintext).await.unwrap();
        drop(writer);

        let mut buf = vec![0u8; MAX_FRAME];

        let (rh1, rp1) = reader.next_frame(&mut buf).await.unwrap();
        assert_eq!(rh1.id, 256);
        assert_eq!(rh1.flags, FLAG_FIRST);
        assert_eq!(rp1, b"foo");

        let (rh2, rp2) = reader.next_frame(&mut buf).await.unwrap();
        assert_eq!(rh2.id, 257);
        assert_eq!(rh2.flags, FLAG_LAST);
        assert_eq!(rp2, b"barbaz");
    }
}
