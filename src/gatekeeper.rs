//! # Text Gatekeeper Engine
//!
//! Multi-pass canonicalization and two-tier regex threat evaluation.
//! Tier 1: Hardcoded fast-path & Dynamic Ban patterns (Instant Ban on join & chat)
//! Tier 2: Dynamic Delete patterns (Soft keyword/link suppression)

use deunicode::deunicode;
use regex::{Regex, RegexSet};
use std::sync::{Arc, RwLock};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ThreatVerdict {
    Safe,
    DeleteOnly,
    InstantBan,
}

pub struct TextGatekeeper {
    hardcoded_patterns: RegexSet,
    dynamic_ban_patterns: Arc<RwLock<Option<RegexSet>>>,
    dynamic_delete_patterns: Arc<RwLock<Option<RegexSet>>>,
}

impl Default for TextGatekeeper {
    fn default() -> Self {
        Self::new()
    }
}

impl TextGatekeeper {
    pub fn new() -> Self {
        let hardcoded = &[
            r"(?i)\bcp\b",
            r"(?i)c+[\._\-\s]*p+[\._\-\s]*(s+t+u+f+|c+o+n+t+e+n+t+|l+i+n+k+|v+i+d+|p+i+c+s?|p+a+c+k+|f+o+l+d+e+r+)",
            r"(?i)c+p+(s+t+u+f+|c+o+n+t+e+n+t+|l+i+n+k+|v+i+d+|p+i+c+s?|p+a+c+k+|f+o+l+d+e+r+)",
            r"(?i)c+[\W_]*p+[\W_a-z]{0,6}(s+t+u+f+|c+o+n+t+e+n+t+|l+i+n+k+|v+i+d+|p+i+c+s?|p+a+c+k+|f+o+l+d+e+r+)",
            r"(?i)m+e+g+a+[\W_a-z]{0,8}(l+i+n+k+|f+o+l+d+e+r+|p+a+c+k+|n+z+|s+t+u+f+)",
            r"(?i)m+e+g+a+(l+i+n+k+|f+o+l+d+e+r+|p+a+c+k+|n+z+|s+t+u+f+)",
            r"(?i)h+o+t+[\W_a-z]{0,8}(l+i+n+k+|f+o+l+d+e+r+|p+a+c+k+|n+z+|s+t+u+f+)",
            r"(?i)h+o+t+(l+i+n+k+|f+o+l+d+e+r+|p+a+c+k+|n+z+|s+t+u+f+)",
            r"(?i)d+s+m+[\W_a-z]{0,6}o+p+e+n+",
            r"(?i)dsmopen",
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
            dynamic_ban_patterns: Arc::new(RwLock::new(None)),
            dynamic_delete_patterns: Arc::new(RwLock::new(None)),
        }
    }

    /// Compiles and updates dynamic rules, cleanly separating instant ban from delete rules
    pub fn reload_dynamic_rules(
        &self,
        ban_patterns: &[String],
        delete_patterns: &[String],
    ) -> Result<(), regex::Error> {
        // 1. Compile Ban Patterns
        if ban_patterns.is_empty() {
            let mut guard = self.dynamic_ban_patterns.write().unwrap();
            *guard = None;
        } else {
            for pat in ban_patterns {
                Regex::new(pat)?;
            }
            let set = RegexSet::new(ban_patterns)?;
            let mut guard = self.dynamic_ban_patterns.write().unwrap();
            *guard = Some(set);
        }

        // 2. Compile Delete Patterns
        if delete_patterns.is_empty() {
            let mut guard = self.dynamic_delete_patterns.write().unwrap();
            *guard = None;
        } else {
            for pat in delete_patterns {
                Regex::new(pat)?;
            }
            let set = RegexSet::new(delete_patterns)?;
            let mut guard = self.dynamic_delete_patterns.write().unwrap();
            *guard = Some(set);
        }

        Ok(())
    }

    pub fn reload_dynamic_patterns(&self, patterns: &[String]) -> Result<(), regex::Error> {
        self.reload_dynamic_rules(&[], patterns)
    }

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

    pub fn canonicalize(&self, input: &str) -> (String, String, String) {
        let mut buffer_homo = String::with_capacity(input.len());
        Self::map_visual_homoglyphs(input, &mut buffer_homo);

        let ascii_mapped = deunicode(&buffer_homo);

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

        let mut alpha_only = String::with_capacity(normalized.len());
        for c in normalized.chars() {
            if c.is_alphanumeric() {
                alpha_only.push(c);
            }
        }

        let mut deduped = String::with_capacity(alpha_only.len());
        Self::collapse_duplicates(&alpha_only, &mut deduped);

        (normalized, alpha_only, deduped)
    }

    pub fn evaluate_threat(&self, raw_text: &str) -> ThreatVerdict {
        if raw_text.is_empty() {
            return ThreatVerdict::Safe;
        }

        let (normalized, alpha_only, deduped) = self.canonicalize(raw_text);

        // 1. TIER 1: Hardcoded fast-path ALWAYS triggers Instant Ban
        if self.hardcoded_patterns.is_match(&normalized)
            || self.hardcoded_patterns.is_match(&alpha_only)
            || self.hardcoded_patterns.is_match(&deduped)
        {
            return ThreatVerdict::InstantBan;
        }

        // 2. TIER 1.5: Dynamic Ban Patterns (Rules marked BAN in dashboard trigger Instant Ban!)
        if let Ok(guard) = self.dynamic_ban_patterns.read() {
            if let Some(ban_set) = &*guard {
                if ban_set.is_match(&normalized)
                    || ban_set.is_match(&alpha_only)
                    || ban_set.is_match(&deduped)
                {
                    return ThreatVerdict::InstantBan;
                }
            }
        }

        // 3. TIER 2: Dynamic Delete Patterns (Soft rules trigger Delete Only)
        if let Ok(guard) = self.dynamic_delete_patterns.read() {
            if let Some(delete_set) = &*guard {
                if delete_set.is_match(&normalized)
                    || delete_set.is_match(&alpha_only)
                    || delete_set.is_match(&deduped)
                {
                    return ThreatVerdict::DeleteOnly;
                }
            }
        }

        ThreatVerdict::Safe
    }

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

        let delete_rules = vec![r"(?i)l+i+n+k+".to_string()];
        gatekeeper.reload_dynamic_rules(&[], &delete_rules).unwrap();

        assert_eq!(
            gatekeeper.evaluate_threat("hotlink0093"),
            ThreatVerdict::InstantBan
        );

        assert_eq!(
            gatekeeper.evaluate_threat("game_link"),
            ThreatVerdict::DeleteOnly
        );
        assert_eq!(
            gatekeeper.evaluate_threat("steam_link_in_bio"),
            ThreatVerdict::DeleteOnly
        );

        assert_eq!(
            gatekeeper.evaluate_threat("normal_gamer_guy"),
            ThreatVerdict::Safe
        );
    }

    #[test]
    fn test_audit_log_missed_accounts_intercepted() {
        let gatekeeper = TextGatekeeper::new();

        let ban_rules = vec![
            r"(?i)m+e+g+a+.*(g+r+o+u+p+|s+e+l+l+|s+e+l+l+e+r+|v+i+d+|s+h+a+r+e+|d+r+i+v+e+)".to_string(),
            r"(?i)(g+o+o+d+|l+e+g+i+t+|r+e+a+l+|b+e+s+t+|c+h+e+a+p+|f+r+e+s+h+|n+e+w+)[\W_]*s+t+u+f+f+".to_string(),
        ];
        gatekeeper.reload_dynamic_rules(&ban_rules, &[]).unwrap();

        let missed_accounts = vec![
            "megagroup0982",
            "goodstuff0472",
            "goodstuff06783",
            "legitstuff0244",
            "latestmegaseller",
            "megaseller0640",
            "cheapstuff99",
            "freshstuff42",
        ];

        for account in missed_accounts {
            assert_eq!(
                gatekeeper.evaluate_threat(account),
                ThreatVerdict::InstantBan,
                "Failed asserting InstantBan for: {}",
                account
            );
        }

        let innocent_gamers = vec![
            "okkotsu_yutadamaki",
            "shikatsuki0954",
            "michael_11_._68674",
            "normal_gamer_guy",
            "good_game_bro",
            "stuffing_turkey_chef",
        ];

        for gamer in innocent_gamers {
            assert_eq!(
                gatekeeper.evaluate_threat(gamer),
                ThreatVerdict::Safe,
                "False positive on innocent user: {}",
                gamer
            );
        }
    }
}
