use crate::error::{ApiError, ApiResult};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub const USERS: [&str;5] = ["grisha","papa","mama","yura","vasya"];
pub fn valid_user(v:&str)->bool { USERS.contains(&v) }
pub fn now() -> DateTime<Utc> { Utc::now() }
pub fn ts(v: DateTime<Utc>) -> String { v.to_rfc3339_opts(SecondsFormat::Nanos, true) }
pub fn parse_ts(v:&str)->anyhow::Result<DateTime<Utc>> { Ok(DateTime::parse_from_rfc3339(v)?.with_timezone(&Utc)) }
pub fn sha256(data:&[u8])->[u8;32] { let mut h=Sha256::new(); h.update(data); h.finalize().into() }
pub fn sha256_hex(data:&[u8])->String { hex::encode(sha256(data)) }
pub fn random_bytes(n:usize)->Vec<u8>{ let mut b=vec![0u8;n]; OsRng.fill_bytes(&mut b); b }
pub fn random_token()->String { URL_SAFE_NO_PAD.encode(random_bytes(32)) }
pub fn b64(v:&[u8])->String { STANDARD.encode(v) }
pub fn b64url(v:&[u8])->String { URL_SAFE_NO_PAD.encode(v) }
pub fn decode_b64(v:&str, max:usize)->ApiResult<Vec<u8>> {
    if v.len()>max.saturating_mul(2)+16 { return Err(ApiError::bad("invalid_encoding")); }
    STANDARD.decode(v).map_err(|_|ApiError::bad("invalid_encoding"))
}
pub fn decode_b64url(v:&str, max:usize)->ApiResult<Vec<u8>> {
    if v.len()>max.saturating_mul(2)+16 { return Err(ApiError::bad("invalid_encoding")); }
    URL_SAFE_NO_PAD.decode(v).map_err(|_|ApiError::bad("invalid_encoding"))
}
pub fn decode_hex32(v:&str)->ApiResult<[u8;32]> {
    let b=hex::decode(v).map_err(|_|ApiError::bad("invalid_digest"))?;
    b.try_into().map_err(|_|ApiError::bad("invalid_digest"))
}
pub fn canonical_uuid(v:&str)->bool { uuid::Uuid::parse_str(v).map(|u|u.to_string()==v).unwrap_or(false) }
pub fn duration_text(d:Duration)->String { if d.as_secs()%3600==0 {format!("{}h",d.as_secs()/3600)} else if d.as_secs()%60==0 {format!("{}m",d.as_secs()/60)} else {format!("{}s",d.as_secs())} }


pub fn render_qr_png(payload: &[u8], minimum_pixels: u32) -> anyhow::Result<Vec<u8>> {
    use qrcode::{Color, QrCode};
    use std::io::Cursor;

    let qr = QrCode::new(payload)?;
    let modules = qr.width();
    let quiet_zone = 4usize;
    let target = minimum_pixels.max(128) as usize;
    let scale = ((target + modules + quiet_zone * 2 - 1) / (modules + quiet_zone * 2)).max(1);
    let side_modules = modules + quiet_zone * 2;
    let side = side_modules * scale;
    let mut pixels = vec![255u8; side * side];
    let colors = qr.to_colors();
    for y in 0..modules {
        for x in 0..modules {
            if colors[y * modules + x] != Color::Dark { continue; }
            let px0 = (x + quiet_zone) * scale;
            let py0 = (y + quiet_zone) * scale;
            for py in py0..py0 + scale {
                let row = py * side;
                for px in px0..px0 + scale { pixels[row + px] = 0; }
            }
        }
    }
    let mut output = Cursor::new(Vec::<u8>::new());
    {
        let mut encoder = png::Encoder::new(&mut output, side as u32, side as u32);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&pixels)?;
    }
    pixels.fill(0);
    Ok(output.into_inner())
}
