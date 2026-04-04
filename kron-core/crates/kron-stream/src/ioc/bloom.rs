//! Counting bloom filter implementation for sub-millisecond IOC lookups.
//!
//! Uses 4-bit packed counters to allow both insertion and deletion while
//! keeping memory usage around 100 MB for 10 million entries at the target
//! 0.01 % false-positive rate.
//!
//! # Design parameters
//!
//! | Parameter | Value | Rationale |
//! |-----------|-------|-----------|
//! | `m` (slots) | 200 000 000 | Achieves ≈0.01 % FP at n = 10 M, k = 7 |
//! | `k` (hash functions) | 7 | Optimal k for m/n = 20 |
//! | Counter width | 4 bits (values 0–15) | Two counters packed per byte → 100 MB |
//! | Hash algorithm | xxHash3-64 with double hashing | Two seeds → k positions |
//!
//! False-positive probability: `(1 - e^(-k·n/m))^k ≈ 0.008 %` at n = 10 M.

use xxhash_rust::xxh3::xxh3_64_with_seed;

/// Counting bloom filter backed by 4-bit packed counters.
///
/// Each logical counter occupies one nibble (4 bits) of a `Vec<u8>`.
/// Two counters share each byte: the low nibble holds an even-indexed counter
/// and the high nibble holds the odd-indexed counter.
///
/// Counters saturate at 15 (max nibble value) to prevent overflow.
pub struct CountingBloomFilter {
    /// Backing storage: `ceil(m / 2)` bytes holding `m` 4-bit counters.
    counters: Vec<u8>,
    /// Total number of 4-bit counter slots.
    m: usize,
    /// Number of hash functions applied per value.
    k: usize,
}

impl CountingBloomFilter {
    /// Create a new filter with `m` counter slots and `k` hash functions.
    ///
    /// `m` is rounded up to the nearest even number so that counter pairs
    /// align cleanly on byte boundaries.
    #[must_use]
    pub fn new(m: usize, k: usize) -> Self {
        // Round up so every counter has a full nibble pair.
        let m_even = if m % 2 == 0 { m } else { m + 1 };
        let byte_len = m_even / 2;
        Self {
            counters: vec![0u8; byte_len],
            m: m_even,
            k,
        }
    }

    /// Insert `data` into the filter, incrementing the k counter positions.
    pub fn insert(&mut self, data: &[u8]) {
        for pos in self.hash_positions(data) {
            self.increment_counter(pos);
        }
    }

    /// Remove one occurrence of `data` from the filter, decrementing k counters.
    ///
    /// Counters will not go below zero. Only call this if you are certain the
    /// value was previously inserted; spurious decrements can cause false
    /// negatives.
    pub fn remove(&mut self, data: &[u8]) {
        for pos in self.hash_positions(data) {
            self.decrement_counter(pos);
        }
    }

    /// Return `true` if `data` is *possibly* present.
    ///
    /// A return value of `false` is a definitive "not present". A return value
    /// of `true` means present with probability `(1 - FP_rate)`.
    #[must_use]
    pub fn check(&self, data: &[u8]) -> bool {
        self.hash_positions(data)
            .into_iter()
            .all(|pos| self.get_counter(pos) > 0)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Read the 4-bit counter at logical position `pos`.
    fn get_counter(&self, pos: usize) -> u8 {
        let byte_idx = pos / 2;
        let byte = self.counters[byte_idx];
        if pos % 2 == 0 {
            byte & 0x0F // low nibble
        } else {
            (byte >> 4) & 0x0F // high nibble
        }
    }

    /// Increment the 4-bit counter at logical position `pos`, saturating at 15.
    fn increment_counter(&mut self, pos: usize) {
        let byte_idx = pos / 2;
        let byte = self.counters[byte_idx];
        if pos % 2 == 0 {
            let val = (byte & 0x0F).min(14);
            self.counters[byte_idx] = (byte & 0xF0) | (val + 1);
        } else {
            let val = ((byte >> 4) & 0x0F).min(14);
            self.counters[byte_idx] = (byte & 0x0F) | ((val + 1) << 4);
        }
    }

    /// Decrement the 4-bit counter at logical position `pos`, flooring at 0.
    fn decrement_counter(&mut self, pos: usize) {
        let byte_idx = pos / 2;
        let byte = self.counters[byte_idx];
        if pos % 2 == 0 {
            let val = byte & 0x0F;
            if val > 0 {
                self.counters[byte_idx] = (byte & 0xF0) | (val - 1);
            }
        } else {
            let val = (byte >> 4) & 0x0F;
            if val > 0 {
                self.counters[byte_idx] = (byte & 0x0F) | ((val - 1) << 4);
            }
        }
    }

    /// Compute the `k` counter positions for `data` using double hashing.
    ///
    /// Uses two independent xxHash3-64 seeds to derive `h1` and `h2`, then
    /// generates positions as `(h1 + i·h2) % m` for `i` in `0..k`.
    fn hash_positions(&self, data: &[u8]) -> Vec<usize> {
        #[allow(clippy::cast_possible_truncation)]
        let h1 = xxh3_64_with_seed(data, 0) as usize;
        // Ensure h2 is odd so the double-hashing sequence covers all slots.
        #[allow(clippy::cast_possible_truncation)]
        let h2 = xxh3_64_with_seed(data, 1) as usize | 1;
        (0..self.k)
            .map(|i| h1.wrapping_add(i.wrapping_mul(h2)) % self.m)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    /// A small filter suitable for unit tests (1 024 slots, k = 7).
    fn small_filter() -> CountingBloomFilter {
        CountingBloomFilter::new(1_024, 7)
    }

    #[test]
    fn test_new_bloom_filter_when_empty_then_check_returns_false() {
        let filter = small_filter();
        assert!(
            !filter.check(b"192.168.1.1"),
            "A brand-new filter must report no values as present"
        );
    }

    #[test]
    fn test_insert_when_value_inserted_then_check_returns_true() {
        let mut filter = small_filter();
        filter.insert(b"malware.example.com");
        assert!(
            filter.check(b"malware.example.com"),
            "A value that was inserted must be found"
        );
    }

    #[test]
    fn test_remove_when_value_removed_then_check_returns_false() {
        let mut filter = small_filter();
        filter.insert(b"10.0.0.1");
        filter.remove(b"10.0.0.1");
        assert!(
            !filter.check(b"10.0.0.1"),
            "A value that was inserted once and then removed must not be found"
        );
    }

    #[test]
    fn test_remove_when_value_inserted_twice_then_check_still_true() {
        let mut filter = small_filter();
        filter.insert(b"deadbeef");
        filter.insert(b"deadbeef");
        filter.remove(b"deadbeef");
        assert!(
            filter.check(b"deadbeef"),
            "After two inserts and one remove the value must still be found"
        );
    }
}
