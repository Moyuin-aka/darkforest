use anyhow::{Context, Result, anyhow, bail, ensure};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, OsRng, rand_core::RngCore},
};

pub const MAGIC: [u8; 4] = *b"DFP1";
pub const NONCE_LEN: usize = 12;
pub const PACKET_LEN: usize = 256;
pub const HEADER_LEN: usize = MAGIC.len() + NONCE_LEN;
pub const CIPHERTEXT_LEN: usize = PACKET_LEN - HEADER_LEN;
pub const PLAINTEXT_LEN: usize = CIPHERTEXT_LEN - 16;
pub const LABEL_LEN: usize = 16;
pub const BODY_LEN: usize = PLAINTEXT_LEN - 1 - 1 - 1 - 2 - 8 - 4 - LABEL_LEN - LABEL_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Dummy = 0,
    Message = 1,
}

impl PacketKind {
    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(Self::Dummy),
            1 => Ok(Self::Message),
            _ => bail!("unknown packet kind {byte}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainPacket {
    pub kind: PacketKind,
    pub sender: String,
    pub target: String,
    pub sent_at: u64,
    pub sequence: u32,
    pub body: String,
}

impl PlainPacket {
    pub fn message(
        sender: impl Into<String>,
        target: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            kind: PacketKind::Message,
            sender: sender.into(),
            target: target.into(),
            sent_at: 0,
            sequence: 0,
            body: body.into(),
        }
    }

    pub fn dummy(sender: impl Into<String>, sequence: u32) -> Self {
        Self {
            kind: PacketKind::Dummy,
            sender: sender.into(),
            target: String::new(),
            sent_at: 0,
            sequence,
            body: String::new(),
        }
    }
}

pub fn parse_key_hex(input: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(input.trim()).context("key must be hex encoded")?;
    ensure!(
        bytes.len() == 32,
        "key must contain exactly 32 bytes (64 hex chars), got {} bytes",
        bytes.len()
    );

    let mut key = [0_u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn generate_key_hex() -> String {
    let mut key = [0_u8; 32];
    OsRng.fill_bytes(&mut key);
    hex::encode(key)
}

pub fn nonce_from_packet(packet: &[u8]) -> Result<[u8; NONCE_LEN]> {
    ensure!(
        packet.len() == PACKET_LEN,
        "packet length must be {PACKET_LEN}"
    );
    ensure!(packet.starts_with(&MAGIC), "missing Dark Forest magic");

    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&packet[MAGIC.len()..HEADER_LEN]);
    Ok(nonce)
}

pub fn seal_packet(
    key: &[u8; 32],
    payload: &PlainPacket,
    rng: &mut impl RngCore,
) -> Result<[u8; PACKET_LEN]> {
    let plaintext = encode_plaintext(payload)?;
    let mut nonce = [0_u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let ciphertext = cipher
        .encrypt((&nonce).into(), plaintext.as_slice())
        .map_err(|_| anyhow!("encryption failed"))?;

    ensure!(
        ciphertext.len() == CIPHERTEXT_LEN,
        "ciphertext length changed unexpectedly: {}",
        ciphertext.len()
    );

    let mut packet = [0_u8; PACKET_LEN];
    packet[..MAGIC.len()].copy_from_slice(&MAGIC);
    packet[MAGIC.len()..HEADER_LEN].copy_from_slice(&nonce);
    packet[HEADER_LEN..].copy_from_slice(&ciphertext);
    Ok(packet)
}

pub fn open_packet(key: &[u8; 32], packet: &[u8]) -> Result<PlainPacket> {
    ensure!(
        packet.len() == PACKET_LEN,
        "packet length must be {PACKET_LEN}"
    );
    ensure!(packet.starts_with(&MAGIC), "missing Dark Forest magic");

    let nonce = &packet[MAGIC.len()..HEADER_LEN];
    let ciphertext = &packet[HEADER_LEN..];
    ensure!(
        ciphertext.len() == CIPHERTEXT_LEN,
        "invalid ciphertext length"
    );

    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| anyhow!("decryption failed"))?;

    ensure!(
        plaintext.len() == PLAINTEXT_LEN,
        "plaintext length changed unexpectedly: {}",
        plaintext.len()
    );

    decode_plaintext(&plaintext)
}

fn encode_plaintext(payload: &PlainPacket) -> Result<[u8; PLAINTEXT_LEN]> {
    ensure!(
        payload.sender.len() <= LABEL_LEN,
        "sender label too long: max {LABEL_LEN} bytes"
    );
    ensure!(
        payload.target.len() <= LABEL_LEN,
        "target label too long: max {LABEL_LEN} bytes"
    );
    ensure!(
        payload.body.len() <= BODY_LEN,
        "message body too long: max {BODY_LEN} bytes"
    );

    let mut out = [0_u8; PLAINTEXT_LEN];
    out[0] = payload.kind as u8;
    out[1] = payload.sender.len() as u8;
    out[2] = payload.target.len() as u8;
    out[3..5].copy_from_slice(&(payload.body.len() as u16).to_be_bytes());
    out[5..13].copy_from_slice(&payload.sent_at.to_be_bytes());
    out[13..17].copy_from_slice(&payload.sequence.to_be_bytes());
    out[17..17 + LABEL_LEN].fill(0);
    out[17..17 + payload.sender.len()].copy_from_slice(payload.sender.as_bytes());
    out[17 + LABEL_LEN..17 + LABEL_LEN + LABEL_LEN].fill(0);
    out[17 + LABEL_LEN..17 + LABEL_LEN + payload.target.len()]
        .copy_from_slice(payload.target.as_bytes());
    out[17 + LABEL_LEN + LABEL_LEN..].fill(0);
    out[17 + LABEL_LEN + LABEL_LEN..17 + LABEL_LEN + LABEL_LEN + payload.body.len()]
        .copy_from_slice(payload.body.as_bytes());
    Ok(out)
}

fn decode_plaintext(plaintext: &[u8]) -> Result<PlainPacket> {
    ensure!(
        plaintext.len() == PLAINTEXT_LEN,
        "plaintext length must be {PLAINTEXT_LEN}"
    );

    let kind = PacketKind::from_byte(plaintext[0])?;
    let sender_len = plaintext[1] as usize;
    let target_len = plaintext[2] as usize;
    let body_len = u16::from_be_bytes([plaintext[3], plaintext[4]]) as usize;
    ensure!(sender_len <= LABEL_LEN, "sender label length out of range");
    ensure!(target_len <= LABEL_LEN, "target label length out of range");
    ensure!(body_len <= BODY_LEN, "body length out of range");

    let sent_at = u64::from_be_bytes(plaintext[5..13].try_into().expect("8-byte timestamp slice"));
    let sequence = u32::from_be_bytes(plaintext[13..17].try_into().expect("4-byte sequence slice"));

    let sender = parse_utf8_field(&plaintext[17..17 + LABEL_LEN], sender_len, "sender")?;
    let target = parse_utf8_field(
        &plaintext[17 + LABEL_LEN..17 + LABEL_LEN + LABEL_LEN],
        target_len,
        "target",
    )?;
    let body = parse_utf8_field(
        &plaintext[17 + LABEL_LEN + LABEL_LEN..17 + LABEL_LEN + LABEL_LEN + BODY_LEN],
        body_len,
        "body",
    )?;

    Ok(PlainPacket {
        kind,
        sender,
        target,
        sent_at,
        sequence,
        body,
    })
}

fn parse_utf8_field(slot: &[u8], len: usize, field_name: &str) -> Result<String> {
    ensure!(len <= slot.len(), "{field_name} length overflow");
    let field = &slot[..len];
    Ok(String::from_utf8(field.to_vec()).context(format!("invalid {field_name} utf-8"))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn message_round_trip_preserves_fields() {
        let key = [7_u8; 32];
        let payload = PlainPacket {
            kind: PacketKind::Message,
            sender: "alice".into(),
            target: "bob".into(),
            sent_at: 1_746_000_123,
            sequence: 9,
            body: "bbq at 8?".into(),
        };
        let mut rng = StdRng::seed_from_u64(42);

        let packet = seal_packet(&key, &payload, &mut rng).expect("seal succeeds");
        let decoded = open_packet(&key, &packet).expect("open succeeds");

        assert_eq!(packet.len(), PACKET_LEN);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn dummy_and_message_share_the_same_packet_length() {
        let key = [9_u8; 32];
        let mut rng = StdRng::seed_from_u64(1);
        let dummy = PlainPacket::dummy("relay-a", 10);
        let message = PlainPacket {
            kind: PacketKind::Message,
            sender: "relay-a".into(),
            target: "relay-b".into(),
            sent_at: 123,
            sequence: 11,
            body: "hello".into(),
        };

        let dummy_packet = seal_packet(&key, &dummy, &mut rng).expect("dummy seal succeeds");
        let real_packet = seal_packet(&key, &message, &mut rng).expect("message seal succeeds");

        assert_eq!(dummy_packet.len(), PACKET_LEN);
        assert_eq!(real_packet.len(), PACKET_LEN);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let key = [5_u8; 32];
        let wrong_key = [6_u8; 32];
        let payload = PlainPacket {
            kind: PacketKind::Message,
            sender: "alice".into(),
            target: "bob".into(),
            sent_at: 100,
            sequence: 1,
            body: "secret".into(),
        };
        let mut rng = StdRng::seed_from_u64(7);
        let packet = seal_packet(&key, &payload, &mut rng).expect("seal succeeds");

        let err = open_packet(&wrong_key, &packet).expect_err("wrong key must fail");
        assert!(err.to_string().contains("decryption failed"));
    }

    #[test]
    fn parse_key_hex_requires_exact_length() {
        let err = parse_key_hex("abcd").expect_err("short key should fail");
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn utf8_body_round_trip_works() {
        let key = [3_u8; 32];
        let payload = PlainPacket {
            kind: PacketKind::Message,
            sender: "甲".into(),
            target: "乙".into(),
            sent_at: 456,
            sequence: 2,
            body: "今晚八点楼下集合".into(),
        };
        let mut rng = StdRng::seed_from_u64(9);

        let packet = seal_packet(&key, &payload, &mut rng).expect("seal succeeds");
        let decoded = open_packet(&key, &packet).expect("open succeeds");

        assert_eq!(decoded, payload);
    }
}
