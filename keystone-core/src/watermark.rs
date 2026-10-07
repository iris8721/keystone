//! Multi-site, variable-offset watermarks.
//!
//! A watermark slot is one occurrence of an operator-configured byte
//! pattern in the artifact plaintext; the pattern's length defines the
//! slot size. At fetch time the server collects up to [`MAX_SITES`]
//! candidate slots, derives a per-download subset of them from
//! HMAC(watermark_secret, "keystone-watermark-sites" || download_id),
//! and overwrites each chosen slot with the same tag:
//! HMAC-SHA256(watermark_secret, "keystone-watermark" || block ||
//! download_id), truncated to the slot size.
//!
//! Everything is a pure function of (watermark_secret, download_id,
//! pattern, pristine plaintext): the tag, the candidate offsets, and the
//! chosen subset reproduce offline, which is what [`locate_watermarks`]
//! uses to grade a suspect copy. Chosen sites carry one identical tag on
//! purpose — a colluder who strips some sites still leaves decodable
//! marks, and a stripped site is distinguishable from an intact one.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Most candidate slots considered per artifact; also the ceiling on the
/// per-download subset.
pub const MAX_SITES: usize = 8;
/// Slots patched per download when the operator does not tune it.
pub const DEFAULT_SITES: usize = 4;

/// Domain separator for the tag HMAC (unchanged since the single-site
/// scheme, so existing tags still verify).
const TAG_DOMAIN: &[u8] = b"keystone-watermark";
/// Domain separator for the site-subset HMAC.
const SITES_DOMAIN: &[u8] = b"keystone-watermark-sites";

/// Deterministic watermark tag for one download: HMAC-SHA256 blocks
/// keyed by the watermark secret over the download id, truncated to
/// `len`. Given a suspect download's id, an operator recomputes these
/// bytes and matches them against the patched regions.
pub fn tag_bytes(secret: &[u8; 32], download_id: &str, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut block = 0u8;
    while out.len() < len {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&secret[..])
            .expect("HMAC accepts any key length");
        mac.update(TAG_DOMAIN);
        mac.update(&[block]);
        mac.update(download_id.as_bytes());
        out.extend_from_slice(&mac.finalize().into_bytes());
        block += 1;
    }
    out.truncate(len);
    out
}

/// Offsets of the first [`MAX_SITES`] non-overlapping occurrences of
/// `pattern`, in ascending order. Non-overlapping keeps the patches from
/// corrupting each other; the scan steps a whole pattern length after
/// every hit.
pub fn candidate_sites(plaintext: &[u8], pattern: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    if pattern.is_empty() {
        return offsets;
    }
    let mut at = 0;
    while offsets.len() < MAX_SITES && at + pattern.len() <= plaintext.len() {
        match plaintext[at..]
            .windows(pattern.len())
            .position(|w| w == pattern)
        {
            Some(pos) => {
                let offset = at + pos;
                offsets.push(offset);
                at = offset + pattern.len();
            }
            None => break,
        }
    }
    offsets
}

/// HMAC-block byte stream over SITES_DOMAIN || block || download_id: the
/// deterministic randomness behind subset selection.
struct SiteRandomness<'a> {
    secret: &'a [u8; 32],
    download_id: &'a str,
    block: u8,
    bytes: [u8; 32],
    /// Position in `bytes`; 32 forces a refill.
    index: usize,
}

impl SiteRandomness<'_> {
    fn new<'a>(secret: &'a [u8; 32], download_id: &'a str) -> SiteRandomness<'a> {
        SiteRandomness {
            secret,
            download_id,
            block: 0,
            bytes: [0u8; 32],
            index: 32,
        }
    }

    fn next_byte(&mut self) -> u8 {
        if self.index == 32 {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.secret[..])
                .expect("HMAC accepts any key length");
            mac.update(SITES_DOMAIN);
            mac.update(&[self.block]);
            mac.update(self.download_id.as_bytes());
            self.bytes = mac.finalize().into_bytes().into();
            self.block = self.block.wrapping_add(1);
            self.index = 0;
        }
        let byte = self.bytes[self.index];
        self.index += 1;
        byte
    }

    /// Uniform draw from 0..bound (1 <= bound <= 256) by rejection
    /// sampling, so no candidate index is favored.
    fn below(&mut self, bound: usize) -> usize {
        debug_assert!((1..=256).contains(&bound));
        let bound = bound as u16;
        let limit = 256 - (256 % bound);
        loop {
            let byte = u16::from(self.next_byte());
            if byte < limit {
                return (byte % bound) as usize;
            }
        }
    }
}

/// The per-download subset: `min(sites, candidates.len())` distinct
/// offsets from `candidates`, chosen by a Fisher–Yates shuffle keyed by
/// HMAC(watermark_secret, "keystone-watermark-sites" || download_id).
/// Returned ascending. `sites` is clamped to 1..=[`MAX_SITES`].
pub fn select_sites(
    secret: &[u8; 32],
    download_id: &str,
    candidates: &[usize],
    sites: usize,
) -> Vec<usize> {
    let n = candidates.len();
    let k = sites.clamp(1, MAX_SITES).min(n);
    if k == 0 {
        return Vec::new();
    }
    let mut order: Vec<usize> = (0..n).collect();
    let mut randomness = SiteRandomness::new(secret, download_id);
    for i in (1..n).rev() {
        let j = randomness.below(i + 1);
        order.swap(i, j);
    }
    let mut chosen: Vec<usize> = order[..k].iter().map(|&i| candidates[i]).collect();
    chosen.sort_unstable();
    chosen
}

/// What [`apply`] did to a plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOutcome {
    /// No pattern occurrence; the bytes are unchanged.
    NotFound,
    /// Exactly one occurrence: the legacy single-site patch (byte-for-
    /// byte identical to the original scheme).
    SingleSite,
    /// Two or more occurrences: `patched` of `candidates` slots now hold
    /// the tag.
    MultiSite {
        /// Slots overwritten with the tag.
        patched: usize,
        /// Candidate slots found.
        candidates: usize,
    },
}

/// Overwrite the per-download subset of `pattern` slots in `plaintext`
/// with the download's tag. With zero occurrences nothing changes; with
/// exactly one the patch is the legacy single-site behavior.
pub fn apply(
    plaintext: &mut [u8],
    pattern: &[u8],
    secret: &[u8; 32],
    download_id: &str,
    sites: usize,
) -> PatchOutcome {
    let candidates = candidate_sites(plaintext, pattern);
    let tag = tag_bytes(secret, download_id, pattern.len());
    match candidates.len() {
        0 => PatchOutcome::NotFound,
        1 => {
            let at = candidates[0];
            plaintext[at..at + pattern.len()].copy_from_slice(&tag);
            PatchOutcome::SingleSite
        }
        count => {
            let chosen = select_sites(secret, download_id, &candidates, sites);
            for &at in &chosen {
                plaintext[at..at + pattern.len()].copy_from_slice(&tag);
            }
            PatchOutcome::MultiSite {
                patched: chosen.len(),
                candidates: count,
            }
        }
    }
}

/// Verdict for one candidate slot in a suspect copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteState {
    /// Chosen for this download and the suspect holds the expected tag.
    Intact,
    /// Chosen for this download but the suspect holds neither the tag
    /// nor the pristine pattern: stripped or corrupted.
    Stripped,
    /// Chosen for this download but the pristine pattern survived; a
    /// served artifact never looks like this.
    Unpatched,
    /// Not chosen for this download; the pristine pattern is expected
    /// here and the slot proves nothing either way.
    Skipped,
}

/// One candidate slot's offset and verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiteMatch {
    /// Byte offset of the slot in the reference (and, barring
    /// length-changing edits, the suspect).
    pub offset: usize,
    /// Whether the suspect holds what this download should have left.
    pub state: SiteState,
}

/// Grade `suspect` against the watermark `reference` (the pristine
/// plaintext) should carry for `download_id`: recompute the candidate
/// slots from the reference, the per-download subset from
/// (watermark_secret, download_id), and the tag, then report each slot.
/// A suspect-only check cannot distinguish "fully stripped" from "never
/// watermarked", which is why the reference is required.
pub fn locate_watermarks(
    reference: &[u8],
    suspect: &[u8],
    pattern: &[u8],
    download_id: &str,
    watermark_secret: &[u8; 32],
    sites: usize,
) -> Vec<SiteMatch> {
    let candidates = candidate_sites(reference, pattern);
    let chosen = select_sites(watermark_secret, download_id, &candidates, sites);
    let tag = tag_bytes(watermark_secret, download_id, pattern.len());
    candidates
        .iter()
        .map(|&offset| {
            let window = suspect.get(offset..offset + pattern.len());
            let state = if !chosen.contains(&offset) {
                SiteState::Skipped
            } else if window == Some(tag.as_slice()) {
                SiteState::Intact
            } else if window == Some(pattern) {
                SiteState::Unpatched
            } else {
                SiteState::Stripped
            };
            SiteMatch { offset, state }
        })
        .collect()
}

/// Match confidence for a [`locate_watermarks`] report: intact chosen
/// slots over total chosen slots. A leak attributed at 1/4 is weak;
/// 3/4 with one stripped slot is strong evidence for this download id.
pub fn match_confidence(matches: &[SiteMatch]) -> (usize, usize) {
    let chosen = matches
        .iter()
        .filter(|m| m.state != SiteState::Skipped)
        .count();
    let intact = matches
        .iter()
        .filter(|m| m.state == SiteState::Intact)
        .count();
    (intact, chosen)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [7u8; 32];
    const PATTERN: &[u8] = b"WATERMARK_SLOT16";

    /// `count` slots of `PATTERN` separated by filler bytes.
    fn artifact(count: usize) -> Vec<u8> {
        let mut bytes = b"header-".to_vec();
        for i in 0..count {
            bytes.extend_from_slice(PATTERN);
            bytes.extend_from_slice(format!("-body{i}-").as_bytes());
        }
        bytes
    }

    #[test]
    fn tag_bytes_are_deterministic_keyed_and_fill_any_length() {
        let a = tag_bytes(&SECRET, "abc", 16);
        assert_eq!(a, tag_bytes(&SECRET, "abc", 16));
        assert_ne!(a, tag_bytes(&SECRET, "abd", 16));
        assert_ne!(a, tag_bytes(&[8u8; 32], "abc", 16));
        let long = tag_bytes(&SECRET, "abc", 100);
        assert_eq!(long.len(), 100);
        assert_eq!(&long[..16], &a[..]);
    }

    #[test]
    fn candidate_sites_are_ascending_non_overlapping_and_capped() {
        // Overlapping hits ("aa" inside "aaaa") collapse to stride steps.
        assert_eq!(candidate_sites(b"aaaaaa", b"aa"), vec![0, 2, 4]);
        let many = artifact(MAX_SITES + 3);
        let offsets = candidate_sites(&many, PATTERN);
        assert_eq!(offsets.len(), MAX_SITES);
        assert!(offsets.windows(2).all(|w| w[0] < w[1]));
        assert!(candidate_sites(b"nothing here", PATTERN).is_empty());
        assert!(candidate_sites(b"anything", b"").is_empty());
    }

    #[test]
    fn the_subset_is_deterministic_per_download_and_varies_across_downloads() {
        let candidates: Vec<usize> = (0..8).map(|i| i * 16).collect();
        let a = select_sites(&SECRET, "dl-a", &candidates, 4);
        assert_eq!(a, select_sites(&SECRET, "dl-a", &candidates, 4));
        assert_eq!(a.len(), 4);
        assert!(a.iter().all(|offset| candidates.contains(offset)));
        assert!(a.windows(2).all(|w| w[0] < w[1]));
        // Another secret picks another subset.
        assert_ne!(a, select_sites(&[9u8; 32], "dl-a", &candidates, 4));
        // Across download ids the subsets are not all one fixed set.
        let sets: Vec<Vec<usize>> = (b'a'..=b'h')
            .map(|c| select_sites(&SECRET, &format!("dl-{}", c as char), &candidates, 4))
            .collect();
        assert!(sets.iter().any(|set| *set != sets[0]));
        // Fewer candidates than sites patches every candidate.
        assert_eq!(
            select_sites(&SECRET, "dl-a", &candidates[..2], 4),
            candidates[..2]
        );
    }

    #[test]
    fn apply_patches_the_chosen_sites_with_the_same_tag() {
        let mut bytes = artifact(5);
        let outcome = apply(&mut bytes, PATTERN, &SECRET, "dl-1", 3);
        assert_eq!(
            outcome,
            PatchOutcome::MultiSite {
                patched: 3,
                candidates: 5
            }
        );
        let tag = tag_bytes(&SECRET, "dl-1", PATTERN.len());
        let candidates = candidate_sites(&artifact(5), PATTERN);
        let chosen = select_sites(&SECRET, "dl-1", &candidates, 3);
        for &at in &candidates {
            let window = &bytes[at..at + PATTERN.len()];
            if chosen.contains(&at) {
                assert_eq!(window, &tag[..], "chosen site at {at}");
            } else {
                assert_eq!(window, PATTERN, "skipped site at {at}");
            }
        }
    }

    #[test]
    fn apply_with_one_occurrence_is_the_legacy_single_site_patch() {
        let mut bytes = artifact(1);
        let before = bytes.clone();
        let outcome = apply(&mut bytes, PATTERN, &SECRET, "dl-1", 4);
        assert_eq!(outcome, PatchOutcome::SingleSite);
        let at = before
            .windows(PATTERN.len())
            .position(|w| w == PATTERN)
            .unwrap();
        assert_eq!(
            &bytes[at..at + PATTERN.len()],
            &tag_bytes(&SECRET, "dl-1", PATTERN.len())[..]
        );
        // Everything outside the slot is untouched.
        assert_eq!(&bytes[..at], &before[..at]);
        assert_eq!(&bytes[at + PATTERN.len()..], &before[at + PATTERN.len()..]);
    }

    #[test]
    fn apply_without_an_occurrence_changes_nothing() {
        let mut bytes = b"no reserved slot here".to_vec();
        let before = bytes.clone();
        assert_eq!(
            apply(&mut bytes, PATTERN, &SECRET, "dl-1", 4),
            PatchOutcome::NotFound
        );
        assert_eq!(bytes, before);
    }

    #[test]
    fn locate_watermarks_finds_intact_sites_and_flags_stripped_ones() {
        let reference = artifact(5);
        let mut suspect = reference.clone();
        assert_eq!(
            apply(&mut suspect, PATTERN, &SECRET, "dl-1", 4),
            PatchOutcome::MultiSite {
                patched: 4,
                candidates: 5
            }
        );
        // Strip one chosen site: overwrite it with junk.
        let candidates = candidate_sites(&reference, PATTERN);
        let chosen = select_sites(&SECRET, "dl-1", &candidates, 4);
        let victim = chosen[1];
        for byte in &mut suspect[victim..victim + PATTERN.len()] {
            *byte = 0xAA;
        }

        let report = locate_watermarks(&reference, &suspect, PATTERN, "dl-1", &SECRET, 4);
        assert_eq!(report.len(), 5);
        for m in &report {
            let expected = if m.offset == victim {
                SiteState::Stripped
            } else if chosen.contains(&m.offset) {
                SiteState::Intact
            } else {
                SiteState::Skipped
            };
            assert_eq!(m.state, expected, "site at {}", m.offset);
        }
        assert_eq!(match_confidence(&report), (3, 4));

        // An untouched reference grades every chosen site Unpatched — a
        // served artifact never looks like this.
        let report = locate_watermarks(&reference, &reference, PATTERN, "dl-1", &SECRET, 4);
        assert_eq!(match_confidence(&report), (0, 4));
        assert!(
            report
                .iter()
                .all(|m| m.state != SiteState::Skipped || !chosen.contains(&m.offset))
        );
        assert!(report.iter().any(|m| m.state == SiteState::Unpatched));

        // The single-site legacy path verifies too: one candidate, chosen.
        let single = artifact(1);
        let mut served = single.clone();
        apply(&mut served, PATTERN, &SECRET, "dl-2", 4);
        let report = locate_watermarks(&single, &served, PATTERN, "dl-2", &SECRET, 4);
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].state, SiteState::Intact);
        assert_eq!(match_confidence(&report), (1, 1));
    }
}
