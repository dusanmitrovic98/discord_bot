use deunicode::deunicode;
use regex::RegexSet;

pub struct TextGatekeeper {
    predatory_patterns: RegexSet,
}

impl TextGatekeeper {
    pub fn new() -> Self {
        let patterns = &[
            // 1. Exact words with word boundaries
            r"(?i)\bcp\b",
            // 2. Patterns with optional separators and character repetition
            r"(?i)c+[\._\-\s]*p+[\._\-\s]*(s+t+u+f+|c+o+n+t+e+n+t+|l+i+n+k+|v+i+d+|p+i+c+s?|p+a+c+k+|f+o+l+d+e+r+)",
            r"(?i)m+e+g+a+[\._\-\s]*(l+i+n+k+|f+o+l+d+e+r+|p+a+c+k+|n+z+|s+t+u+f+)",
            // 3. Direct continuous matches for alphanumeric projections (Handles 'mmmeeegggaaallliinnkk')
            r"(?i)c+p+(s+t+u+f+|c+o+n+t+e+n+t+|l+i+n+k+|v+i+d+|p+i+c+s?|p+a+c+k+|f+o+l+d+e+r+)",
            r"(?i)m+e+g+a+(l+i+n+k+|f+o+l+d+e+r+|p+a+c+k+|n+z+|s+t+u+f+)",
            // 4. Noise symbol injections (e.g., cp_@#$$!%STUf1)
            r"(?i)c+[\W_]*p+[\W_a-z]{0,6}(s+t+u+f+|c+o+n+t+e+n+t+|l+i+n+k+|v+i+d+|p+i+c+s?|p+a+c+k+|f+o+l+d+e+r+)",
            // 5. Zero-tolerance predatory keywords
            r"(?i)child[\._\-\s]*(porn|sex|abuse)",
            r"(?i)child(porn|sex|abuse)",
            r"(?i)ped[o0]",
            r"(?i)pre[\-_]?teen",
            r"(?i)cheese[\._\-\s]*pizza",
            r"(?i)cheesepizza",
        ];

        let predatory_patterns =
            RegexSet::new(patterns).expect("Gatekeeper regex rules must compile");
        Self { predatory_patterns }
    }

    /// Explicit visual homoglyph mapping: Cyrillic & Greek characters mapped to Latin visual twins
    fn map_visual_homoglyphs(text: &str) -> String {
        text.chars()
            .map(|c| match c {
                'С' | 'с' => 'c', // Cyrillic Es
                'Р' | 'р' => 'p', // Cyrillic Er (visually 'P')
                'ѕ' => 's',       // Cyrillic Dze
                'т' => 't',       // Cyrillic Te
                'υ' => 'u',       // Greek Upsilon
                'а' | 'А' => 'a',
                'е' | 'Е' => 'e',
                'о' | 'О' => 'o',
                'і' | 'І' => 'i',
                other => other,
            })
            .collect()
    }

    /// Collapses consecutive duplicate characters: "mmmeeegggaaallliinnkk" -> "megalink"
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

    /// Multi-pass canonicalization:
    /// Returns: (normalized, alpha_only, deduped)
    pub fn canonicalize(&self, input: &str) -> (String, String, String) {
        // 1. Visual homoglyphs mapped
        let homoglyphs_mapped = Self::map_visual_homoglyphs(input);

        // 2. Transliterate remaining full-width Unicode
        let ascii_mapped = deunicode(&homoglyphs_mapped);

        // 3. Lowercase and strip control characters & zero-width spaces
        let cleaned: String = ascii_mapped
            .to_lowercase()
            .chars()
            .filter(|c| !c.is_control() && *c != '\u{200B}' && *c != '\u{FEFF}')
            .collect();

        // 4. Leet-speak substitution
        let normalized = cleaned
            .replace('0', "o")
            .replace('1', "i")
            .replace('3', "e")
            .replace('4', "a")
            .replace('5', "s")
            .replace('7', "t")
            .replace('@', "a")
            .replace('$', "s");

        // 5. Alphanumeric projection (strips punctuation & delimiters)
        let alpha_only: String = normalized.chars().filter(|c| c.is_alphanumeric()).collect();

        // 6. Deduplicated projection (collapses repeated characters)
        let deduped: String = Self::collapse_duplicates(&alpha_only);

        (normalized, alpha_only, deduped)
    }

    /// Evaluates whether a text or username violates zero-tolerance safety policies across all projections.
    pub fn is_flagged(&self, raw_text: &str) -> bool {
        let (normalized, alpha_only, deduped) = self.canonicalize(raw_text);
        self.predatory_patterns.is_match(&normalized)
            || self.predatory_patterns.is_match(&alpha_only)
            || self.predatory_patterns.is_match(&deduped)
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
}
