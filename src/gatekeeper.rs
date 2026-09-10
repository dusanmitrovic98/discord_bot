use deunicode::deunicode;
use regex::{Regex, RegexSet};
use std::sync::{Arc, RwLock};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ThreatVerdict {
    Safe,
    DeleteOnly, // Soft rule (e.g. 'link' in display name -> delete message, NO ban)
    InstantBan, // Hardcoded predatory raid rule (e.g. 'hotlink', 'megalink', 'cp' -> instant ban)
}

pub struct TextGatekeeper {
    hardcoded_patterns: RegexSet,
    dynamic_patterns: Arc<RwLock<Option<RegexSet>>>,
}

impl Default for TextGatekeeper {
    fn default() -> Self {
        Self::new()
    }
}

impl TextGatekeeper {
    pub fn new() -> Self {
        let hardcoded = &[
            // 1. Exact words with word boundaries
            r"(?i)\bcp\b",
            // 2. CP variants with arbitrary separators & repetition
            r"(?i)c+[\._\-\s]*p+[\._\-\s]*(s+t+u+f+|c+o+n+t+e+n+t+|l+i+n+k+|v+i+d+|p+i+c+s?|p+a+c+k+|f+o+l+d+e+r+)",
            r"(?i)c+p+(s+t+u+f+|c+o+n+t+e+n+t+|l+i+n+k+|v+i+d+|p+i+c+s?|p+a+c+k+|f+o+l+d+e+r+)",
            r"(?i)c+[\W_]*p+[\W_a-z]{0,6}(s+t+u+f+|c+o+n+t+e+n+t+|l+i+n+k+|v+i+d+|p+i+c+s?|p+a+c+k+|f+o+l+d+e+r+)",
            // 3. Mega Link variants (Immune to emoji injections like MEGA 🔥 LINK)
            r"(?i)m+e+g+a+[\W_a-z]{0,8}(l+i+n+k+|f+o+l+d+e+r+|p+a+c+k+|n+z+|s+t+u+f+)",
            r"(?i)m+e+g+a+(l+i+n+k+|f+o+l+d+e+r+|p+a+c+k+|n+z+|s+t+u+f+)",
            // 4. HARDCODED HOTLINK & RAID VECTORS (Fast-Path, matches 'HOT 🔥 LINK')
            r"(?i)h+o+t+[\W_a-z]{0,8}(l+i+n+k+|f+o+l+d+e+r+|p+a+c+k+|n+z+|s+t+u+f+)",
            r"(?i)h+o+t+(l+i+n+k+|f+o+l+d+e+r+|p+a+c+k+|n+z+|s+t+u+f+)",
            r"(?i)d+s+m+[\W_a-z]{0,6}o+p+e+n+",
            r"(?i)dsmopen",
            // 5. Zero-tolerance predatory keywords
            r"(?i)child[\._\-\s]*(porn|sex|abuse)",
            r"(?i)child(porn|sex|abuse)",
            r"(?i)ped[o0]",
            r"(?i)pre[\-_]?teen",
            r"(?i)cheese[\._\-\s]*pizza",
            r"(?i)cheesepizza",
        ];

        let hardcoded_patterns =
            RegexSet::new(hardcoded).expect("Hardcoded regex rules must compile");
        Self {
            hardcoded_patterns,
            dynamic_patterns: Arc::new(RwLock::new(None)),
        }
    }

    /// Loads custom dynamic regexes from MongoDB into memory without server restarts
    pub fn reload_dynamic_patterns(&self, patterns: &[String]) -> Result<(), regex::Error> {
        if patterns.is_empty() {
            let mut guard = self.dynamic_patterns.write().unwrap();
            *guard = None;
            return Ok(());
        }

        // Validate each regex individually first (NASA Rule 5)
        for pat in patterns {
            Regex::new(pat)?;
        }

        let new_set = RegexSet::new(patterns)?;
        let mut guard = self.dynamic_patterns.write().unwrap();
        *guard = Some(new_set);
        Ok(())
    }

    /// Map visual homoglyphs into a pre-allocated buffer
    fn map_visual_homoglyphs(text: &str, out: &mut String) {
        out.clear();
        out.reserve(text.len());
        for c in text.chars() {
            let mapped = match c {
                'С' | 'с' => 'c',
                'Р' | 'р' => 'p',
                'ѕ' => 's',
                'т' => 't',
                'υ' => 'u',
                'а' | 'А' => 'a',
                'е' | 'Е' => 'e',
                'о' | 'О' => 'o',
                'і' | 'І' => 'i',
                other => other,
            };
            out.push(mapped);
        }
    }

    /// Collapses consecutive duplicate characters into a pre-allocated buffer
    fn collapse_duplicates(input: &str, out: &mut String) {
        out.clear();
        out.reserve(input.len());
        let mut prev: Option<char> = None;
        for c in input.chars() {
            if Some(c) != prev {
                out.push(c);
                prev = Some(c);
            }
        }
    }

    /// Allocation-optimized multi-pass canonicalization
    pub fn canonicalize(&self, input: &str) -> (String, String, String) {
        // Buffer 1: Homoglyphs
        let mut buffer_homo = String::with_capacity(input.len());
        Self::map_visual_homoglyphs(input, &mut buffer_homo);

        // Buffer 2: Transliterated ASCII
        let ascii_mapped = deunicode(&buffer_homo);

        // Buffer 3: Cleaned & Leet-normalized
        let mut normalized = String::with_capacity(ascii_mapped.len());
        for c in ascii_mapped.chars() {
            if c.is_control() || c == '\u{200B}' || c == '\u{FEFF}' {
                continue;
            }
            let lower = c.to_ascii_lowercase();
            let leet = match lower {
                '0' => 'o',
                '1' => 'i',
                '3' => 'e',
                '4' => 'a',
                '5' => 's',
                '7' => 't',
                '@' => 'a',
                '$' => 's',
                other => other,
            };
            normalized.push(leet);
        }

        // Buffer 4: Alphanumeric projection
        let mut alpha_only = String::with_capacity(normalized.len());
        for c in normalized.chars() {
            if c.is_alphanumeric() {
                alpha_only.push(c);
            }
        }

        // Buffer 5: Deduplicated projection
        let mut deduped = String::with_capacity(alpha_only.len());
        Self::collapse_duplicates(&alpha_only, &mut deduped);

        (normalized, alpha_only, deduped)
    }

    /// Evaluates threat severity using the two-tier execution hierarchy
    pub fn evaluate_threat(&self, raw_text: &str) -> ThreatVerdict {
        if raw_text.is_empty() {
            return ThreatVerdict::Safe;
        }

        let (normalized, alpha_only, deduped) = self.canonicalize(raw_text);

        // TIER 1: Hardcoded fast-path ALWAYS triggers Instant Ban in <1μs
        if self.hardcoded_patterns.is_match(&normalized)
            || self.hardcoded_patterns.is_match(&alpha_only)
            || self.hardcoded_patterns.is_match(&deduped)
        {
            return ThreatVerdict::InstantBan;
        }

        // TIER 2: Dynamic RAM Cache (Soft rules trigger Delete Only)
        if let Ok(guard) = self.dynamic_patterns.read() {
            if let Some(dynamic_set) = &*guard {
                if dynamic_set.is_match(&normalized)
                    || dynamic_set.is_match(&alpha_only)
                    || dynamic_set.is_match(&deduped)
                {
                    return ThreatVerdict::DeleteOnly;
                }
            }
        }

        ThreatVerdict::Safe
    }

    /// Backward-compatible boolean check for existing tests
    pub fn is_flagged(&self, raw_text: &str) -> bool {
        self.evaluate_threat(raw_text) != ThreatVerdict::Safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raid_exact_accounts_instant_ban() {
        let gatekeeper = TextGatekeeper::new();

        let attacks = vec![
            "cpstuuf",
            "cpstuff08143",
            "megalink08225",
            "megalink08816",
            "megalink0588",
            "megalinkstuff0680",
            "hotlink0093",
            "HOT 🔥 LINK",
            "dsm open",
            "dsmopen",
        ];

        for username in attacks {
            assert_eq!(
                gatekeeper.evaluate_threat(username),
                ThreatVerdict::InstantBan,
                "Failed asserting InstantBan for: {}",
                username
            );
        }
    }

    #[test]
    fn test_dynamic_soft_rule_hierarchy() {
        let gatekeeper = TextGatekeeper::new();

        let dynamic_rules = vec![r"(?i)l+i+n+k+".to_string()];
        gatekeeper.reload_dynamic_patterns(&dynamic_rules).unwrap();

        // Hardcoded hotlink hits Tier 1 first (InstantBan)
        assert_eq!(
            gatekeeper.evaluate_threat("hotlink0093"),
            ThreatVerdict::InstantBan
        );

        // Generic link hits Tier 2 (DeleteOnly)
        assert_eq!(
            gatekeeper.evaluate_threat("game_link"),
            ThreatVerdict::DeleteOnly
        );
        assert_eq!(
            gatekeeper.evaluate_threat("steam_link_in_bio"),
            ThreatVerdict::DeleteOnly
        );

        // Normal name is Safe
        assert_eq!(
            gatekeeper.evaluate_threat("normal_gamer_guy"),
            ThreatVerdict::Safe
        );
    }
}
