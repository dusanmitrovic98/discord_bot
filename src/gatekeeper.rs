use deunicode::deunicode;
use regex::{Regex, RegexSet};
use std::sync::{Arc, RwLock};

pub struct TextGatekeeper {
    hardcoded_patterns: RegexSet,
    dynamic_patterns: Arc<RwLock<Option<RegexSet>>>,
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

    fn map_visual_homoglyphs(text: &str) -> String {
        text.chars()
            .map(|c| match c {
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
            })
            .collect()
    }

    fn collapse_duplicates(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let mut prev: Option<char> = None;
        for c in s.chars() {
            if Some(c) != prev {
                result.push(c);
                prev = Some(c);
            }
        }
        result
    }

    pub fn canonicalize(&self, input: &str) -> (String, String, String) {
        let homoglyphs_mapped = Self::map_visual_homoglyphs(input);
        let ascii_mapped = deunicode(&homoglyphs_mapped);
        let cleaned: String = ascii_mapped
            .to_lowercase()
            .chars()
            .filter(|c| !c.is_control() && *c != '\u{200B}' && *c != '\u{FEFF}')
            .collect();

        let normalized = cleaned
            .replace('0', "o")
            .replace('1', "i")
            .replace('3', "e")
            .replace('4', "a")
            .replace('5', "s")
            .replace('7', "t")
            .replace('@', "a")
            .replace('$', "s");

        let alpha_only: String = normalized.chars().filter(|c| c.is_alphanumeric()).collect();
        let deduped: String = Self::collapse_duplicates(&alpha_only);

        (normalized, alpha_only, deduped)
    }

    /// Two-Tier Fast-Path Evaluation
    pub fn is_flagged(&self, raw_text: &str) -> bool {
        let (normalized, alpha_only, deduped) = self.canonicalize(raw_text);

        // =====================================================================
        // TIER 1: FAST-PATH (Hardcoded patterns run in <1 microsecond)
        // =====================================================================
        if self.hardcoded_patterns.is_match(&normalized)
            || self.hardcoded_patterns.is_match(&alpha_only)
            || self.hardcoded_patterns.is_match(&deduped)
        {
            return true; // Match found immediately; zero database overhead!
        }

        // =====================================================================
        // TIER 2: DYNAMIC RAM CACHE (Evaluated only if fast-path passes)
        // =====================================================================
        if let Ok(guard) = self.dynamic_patterns.read() {
            if let Some(dynamic_set) = &*guard {
                if dynamic_set.is_match(&normalized)
                    || dynamic_set.is_match(&alpha_only)
                    || dynamic_set.is_match(&deduped)
                {
                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catches_all_architect_reported_variants() {
        let gatekeeper = TextGatekeeper::new();

        let attacks = vec![
            "cpstuuf",
            "cpstuff08143",
            "megalink08225",
            "megalink08816",
            "megalink0588",
            "megalinkstuff0680",
        ];

        for username in attacks {
            assert!(
                gatekeeper.is_flagged(username),
                "Failed to catch: {}",
                username
            );
        }
    }

    #[test]
    fn test_catches_obfuscated_homoglyphs_and_leetspeak() {
        let gatekeeper = TextGatekeeper::new();

        let evasions = vec![
            "M-E-G-A---L-I-N-K",
            "c.p. stuff",
            "m3g4 l1nk",
            "CP_STUFF_999",
            "c p  stuff",
            "ｍｅｇａ ｌｉｎｋ",
            "СР ѕтυff",
            "mmmeeegggaaallliinnkk",
        ];

        for evasion in evasions {
            assert!(
                gatekeeper.is_flagged(evasion),
                "Failed to catch: {}",
                evasion
            );
        }
    }

    #[test]
    fn test_legitimate_usernames_are_safe() {
        let gatekeeper = TextGatekeeper::new();

        let benign = vec![
            "bubbly_quokka_34489",
            "stylish_peacock_82532",
            "jamesaccess0570",
            "hyperion_prime",
            "rustacean_engineer",
            "normal_gamer_guy",
            "mega_man_classic_fan",
        ];

        for user in benign {
            assert!(
                !gatekeeper.is_flagged(user),
                "False positive on safe user: {}",
                user
            );
        }
    }

    #[test]
    fn test_hardcoded_hotlink_and_dsm_open() {
        let gatekeeper = TextGatekeeper::new();

        // Exact attack patterns from the Architect's screenshot
        assert!(gatekeeper.is_flagged("hotlink0093"));
        assert!(gatekeeper.is_flagged("HOT 🔥 LINK"));
        assert!(gatekeeper.is_flagged("h-o-t---l-i-n-k"));
        assert!(gatekeeper.is_flagged("DSM open DSM open DSM open"));
        assert!(gatekeeper.is_flagged("dsmopen"));

        // Benign names remain safe
        assert!(!gatekeeper.is_flagged("hotel_california"));
        assert!(!gatekeeper.is_flagged("shotgun_hero"));
    }
}
