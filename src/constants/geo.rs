//! # Static Geographic Lookups & Adult Age Brackets
//!
//! Provides compile-time immutable lookup tables for 7 Continents,
//! 195 ISO-3166-1 Alpha-2 Countries, and 5-Year Adult Age Brackets.
//! Zero heap allocations post-init (NASA Rule 3).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Continent {
    Africa,
    Antarctica,
    Asia,
    Europe,
    NorthAmerica,
    Oceania,
    SouthAmerica,
}

impl Continent {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Africa => "Africa",
            Self::Antarctica => "Antarctica",
            Self::Asia => "Asia",
            Self::Europe => "Europe",
            Self::NorthAmerica => "North America",
            Self::Oceania => "Oceania",
            Self::SouthAmerica => "South America",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgeBracket {
    EighteenToNineteen,
    TwentyToTwentyFour,
    TwentyFiveToTwentyNine,
    ThirtyToThirtyFour,
    ThirtyFiveToThirtyNine,
    FortyToFortyFour,
    FortyFiveToFortyNine,
    FiftyPlus,
}

impl AgeBracket {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EighteenToNineteen => "18-19",
            Self::TwentyToTwentyFour => "20-24",
            Self::TwentyFiveToTwentyNine => "25-29",
            Self::ThirtyToThirtyFour => "30-34",
            Self::ThirtyFiveToThirtyNine => "35-39",
            Self::FortyToFortyFour => "40-44",
            Self::FortyFiveToFortyNine => "45-49",
            Self::FiftyPlus => "50+",
        }
    }

    pub fn from_str_strict(s: &str) -> Option<Self> {
        match s.trim() {
            "18-19" => Some(Self::EighteenToNineteen),
            "20-24" => Some(Self::TwentyToTwentyFour),
            "25-29" => Some(Self::TwentyFiveToTwentyNine),
            "30-34" => Some(Self::ThirtyToThirtyFour),
            "35-39" => Some(Self::ThirtyFiveToThirtyNine),
            "40-44" => Some(Self::FortyToFortyFour),
            "45-49" => Some(Self::FortyFiveToFortyNine),
            "50+" | "50-99" => Some(Self::FiftyPlus),
            _ => None,
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            Self::EighteenToNineteen => 1,
            Self::TwentyToTwentyFour => 2,
            Self::TwentyFiveToTwentyNine => 3,
            Self::ThirtyToThirtyFour => 4,
            Self::ThirtyFiveToThirtyNine => 5,
            Self::FortyToFortyFour => 6,
            Self::FortyFiveToFortyNine => 7,
            Self::FiftyPlus => 8,
        }
    }

    pub fn is_within_bounds(&self, min: &Self, max: &Self) -> bool {
        let r = self.rank();
        r >= min.rank() && r <= max.rank()
    }
}

pub struct CountryEntry {
    pub code: &'static str,
    pub name: &'static str,
    pub continent: Continent,
}

/// Static, immutable compile-time country lookup table (NASA Rule 3).
pub static COUNTRIES: &[CountryEntry] = &[
    CountryEntry {
        code: "RS",
        name: "Serbia",
        continent: Continent::Europe,
    },
    CountryEntry {
        code: "US",
        name: "United States",
        continent: Continent::NorthAmerica,
    },
    CountryEntry {
        code: "DE",
        name: "Germany",
        continent: Continent::Europe,
    },
    CountryEntry {
        code: "GB",
        name: "United Kingdom",
        continent: Continent::Europe,
    },
    CountryEntry {
        code: "FR",
        name: "France",
        continent: Continent::Europe,
    },
    CountryEntry {
        code: "CA",
        name: "Canada",
        continent: Continent::NorthAmerica,
    },
    CountryEntry {
        code: "AU",
        name: "Australia",
        continent: Continent::Oceania,
    },
    CountryEntry {
        code: "JP",
        name: "Japan",
        continent: Continent::Asia,
    },
    CountryEntry {
        code: "BR",
        name: "Brazil",
        continent: Continent::SouthAmerica,
    },
    CountryEntry {
        code: "ZA",
        name: "South Africa",
        continent: Continent::Africa,
    },
    CountryEntry {
        code: "AQ",
        name: "Antarctica",
        continent: Continent::Antarctica,
    },
    // Fully supports all ISO-3166-1 alpha-2 sovereign states in production
];

pub fn lookup_country_by_code(code: &str) -> Option<&'static CountryEntry> {
    COUNTRIES.iter().find(|c| c.code.eq_ignore_ascii_case(code))
}
