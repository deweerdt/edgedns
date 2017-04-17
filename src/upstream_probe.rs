use base64;
use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};
use coarsetime::{Clock, Duration};
use siphasher::sip::SipHasher13;
use std::hash::Hasher;
use std::io::Cursor;

const PROBE_PREFIX: &[u8] = b"edgedns-probe-";
const PROBE_KEY_LEN: usize = 12;
const PROBE_KEY_B64_LEN: usize = 16;

pub struct UpstreamProbe;

impl UpstreamProbe {
    fn compute_probe_name(probe_suffix: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut hasher = SipHasher13::new();
        let mut probe_key = Vec::with_capacity(PROBE_KEY_LEN);
        let now_secs = Clock::recent_since_epoch().as_secs();
        probe_key
            .write_u32::<NativeEndian>(now_secs as u32)
            .unwrap();
        hasher.write_u32(now_secs as u32);
        probe_key
            .write_u64::<NativeEndian>(hasher.finish())
            .unwrap();
        let probe_key_b64 = base64::encode_config(&probe_key, base64::URL_SAFE_NO_PAD);
        let probe_key_b64 = probe_key_b64.as_bytes();
        let mut probe_name = Vec::with_capacity(1 + PROBE_PREFIX.len() + probe_key_b64.len() + 1 +
                                                probe_suffix.len() +
                                                1);
        probe_name.push((PROBE_PREFIX.len() + probe_key_b64.len()) as u8);
        probe_name.extend(PROBE_PREFIX);
        probe_name.extend(probe_key_b64);
        if !probe_suffix.is_empty() {
            probe_name.push(probe_suffix.len() as u8);
            probe_name.extend(probe_suffix);
        }
        probe_name.push(0u8);
        Ok(probe_name)
    }

    fn verify_probe_name(probe_name: &[u8], probe_suffix: &[u8]) -> Result<(), &'static str> {
        let probe_prefix_len = PROBE_PREFIX.len();
        let probe_suffix_len_with_terminator = if probe_suffix.is_empty() {
            0
        } else {
            probe_suffix.len() + 1
        };
        if probe_name.len() !=
           1 + probe_prefix_len + PROBE_KEY_B64_LEN + 1 + probe_suffix_len_with_terminator {
            return Err("Name length doesn't match the length of a valid probe");
        }
        if probe_name.is_empty() ||
           probe_name[0] as usize != probe_prefix_len + PROBE_KEY_B64_LEN ||
           !probe_name[1..].starts_with(PROBE_PREFIX) {
            return Err("Probe prefix doesn't match");
        }
        let probe_key_b64 = &probe_name[1 + probe_prefix_len..
                             (probe_name.len() - probe_suffix_len_with_terminator - 1)];
        let probe_key = match base64::decode_config(probe_key_b64, base64::URL_SAFE_NO_PAD) {
            Ok(probe_key) => probe_key,
            _ => return Err("Unable to decode the key"),
        };
        if probe_key.len() != PROBE_KEY_LEN {
            return Err("Decoded key doesn't have the expected length");
        }
        let mut probe_key_c = Cursor::new(probe_key);
        let ts_secs = probe_key_c.read_u32::<NativeEndian>().unwrap() as u64;
        let now_secs = Clock::recent_since_epoch().as_secs();
        if ts_secs < now_secs || ts_secs - now_secs > 10 {
            return Err("Probe response is too old");
        }
        let expected_h = probe_key_c.read_u64::<NativeEndian>().unwrap();
        let mut hasher = SipHasher13::new();
        hasher.write_u32(now_secs as u32);
        if hasher.finish() != expected_h {
            return Err("Wrong hash for the given probe");
        }
        Ok(())
    }
}
