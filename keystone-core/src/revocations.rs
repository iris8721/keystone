//! The revoked issuer key id file: a JSON array of key ids, e.g. `[1, 3]`.

use std::collections::BTreeSet;

use crate::error::{KeystoneError, Result};

/// Parse a revocations file. An empty or whitespace-only file is the empty
/// set; anything but a JSON array of integers in `0..=255` is `Malformed`.
pub fn parse(bytes: &[u8]) -> Result<BTreeSet<u8>> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(BTreeSet::new());
    }
    serde_json::from_slice(bytes)
        .map_err(|e| KeystoneError::Malformed(format!("revocations file: {e}")))
}

/// Encode a set as the file format [`parse`] reads: an ascending JSON array.
pub fn serialize(ids: &BTreeSet<u8>) -> Vec<u8> {
    serde_json::to_vec(ids).expect("a set of integers always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_as_a_json_array() {
        let ids = BTreeSet::from([3, 1, 255]);
        assert_eq!(serialize(&ids), b"[1,3,255]");
        assert_eq!(parse(&serialize(&ids)).unwrap(), ids);
        assert_eq!(parse(b"[2, 2]").unwrap(), BTreeSet::from([2]));
    }

    #[test]
    fn empty_file_is_the_empty_set() {
        assert!(parse(b"").unwrap().is_empty());
        assert!(parse(b" \n").unwrap().is_empty());
        assert!(parse(b"[]").unwrap().is_empty());
    }

    #[test]
    fn rejects_anything_but_an_array_of_key_ids() {
        for bad in [
            &b"[256]"[..],
            b"[-1]",
            b"{\"ids\":[1]}",
            b"1",
            b"[1,",
            b"[\"1\"]",
        ] {
            assert!(
                matches!(parse(bad), Err(KeystoneError::Malformed(_))),
                "{:?} accepted",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
