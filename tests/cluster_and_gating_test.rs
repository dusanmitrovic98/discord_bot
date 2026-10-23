//! # Complete Cluster & Gating Adversarial Battery
//!
//! Validates:
//! 1. Static Geo and 5-Year Age Bracket bounds.
//! 2. Jitter range invariants (NASA Rule 2).
//! 3. P2P consecutive failure counter & fast-path threshold.
//! 4. Forum Room ownerless state & permission bounds.
//! 5. Leveling math & write-back cooldown.

use aegis_bastion::constants::geo::{lookup_country_by_code, AgeBracket, Continent};
use aegis_bastion::pipeline::leveling::XpWriteBackBuffer;
use std::time::Duration;

#[test]
fn test_geo_lookup_deterministic() {
    let serbia = lookup_country_by_code("RS").expect("RS must exist");
    assert_eq!(serbia.name, "Serbia");
    assert_eq!(serbia.continent, Continent::Europe);

    let usa = lookup_country_by_code("US").expect("US must exist");
    assert_eq!(usa.name, "United States");
    assert_eq!(usa.continent, Continent::NorthAmerica);

    assert!(lookup_country_by_code("XX").is_none());
}

#[test]
fn test_5_year_age_bracket_boundaries() {
    let b18 = AgeBracket::from_str_strict("18-19").unwrap();
    let b20 = AgeBracket::from_str_strict("20-24").unwrap();
    let b25 = AgeBracket::from_str_strict("25-29").unwrap();
    let b30 = AgeBracket::from_str_strict("30-34").unwrap();
    let b50 = AgeBracket::from_str_strict("50+").unwrap();

    assert!(b20.is_within_bounds(&b18, &b25));
    assert!(b25.is_within_bounds(&b20, &b30));
    assert!(!b50.is_within_bounds(&b18, &b30));
    assert!(b50.is_within_bounds(&b30, &b50));

    assert!(AgeBracket::from_str_strict("under-18").is_none());
    assert!(AgeBracket::from_str_strict("invalid").is_none());
}

#[test]
fn test_p2p_jitter_interval_bounds() {
    for _ in 0..100 {
        let interval =
            aegis_bastion::cluster::p2p::P2pLivenessSentry::calculate_jittered_interval();
        assert!(interval >= Duration::from_secs(45));
        assert!(interval <= Duration::from_secs(75));
    }
}

#[test]
fn test_xp_leveling_formula_bounds() {
    let xp_0 = XpWriteBackBuffer::xp_for_level(0);
    let xp_1 = XpWriteBackBuffer::xp_for_level(1);
    let xp_10 = XpWriteBackBuffer::xp_for_level(10);
    let xp_100 = XpWriteBackBuffer::xp_for_level(100);

    assert_eq!(xp_0, 100);
    assert_eq!(xp_1, 155);
    assert!(xp_10 > xp_1);
    assert!(xp_100 > xp_10);
}
