//! The masking engine: runs every rule, then merges the hits into disjoint spans.

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::sync::Mutex;
use std::thread;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use memchr::memchr;
use regex::Regex;

use crate::rules::{self, ENTITIES, Validator};

/// Batches smaller than this are faster on one thread than spawning workers.
const PARALLEL_MIN_BYTES: usize = 256 * 1024;
const BATCH_CHUNK_DOCS: usize = 32;

pub const DEFAULT_TEMPLATE: &str = "[{entity}_REDACTED]";

#[derive(Clone, Debug)]
pub struct MaskerConfig {
    pub entities: Vec<String>,
    pub custom_patterns: Vec<(String, String)>,
    pub deny_list: Vec<(String, Vec<String>)>,
    pub allow_list: Vec<String>,
    pub template: String,
}

impl Default for MaskerConfig {
    fn default() -> Self {
        Self {
            entities: ENTITIES.iter().map(ToString::to_string).collect(),
            custom_patterns: Vec::new(),
            deny_list: Vec::new(),
            allow_list: Vec::new(),
            template: DEFAULT_TEMPLATE.to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// A detected entity as byte offsets into the UTF-8 text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub label: usize,
    pub start: usize,
    pub end: usize,
}

struct Detector {
    label: usize,
    regex: Regex,
    validate: Option<Validator>,
    required_byte: Option<u8>,
    value_group: bool,
}

struct DenyList {
    matcher: AhoCorasick,
    labels: Vec<usize>,
}

pub struct Masker {
    labels: Vec<String>,
    replacements: Vec<String>,
    detectors: Vec<Detector>,
    deny: Option<DenyList>,
    allow: HashSet<String>,
}

fn valid_entity_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_uppercase())
        && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn label_of(labels: &mut Vec<String>, name: &str) -> Result<usize, ConfigError> {
    if !valid_entity_name(name) {
        return Err(ConfigError(format!(
            "invalid entity name {name:?}: expected uppercase letters, digits and underscores"
        )));
    }
    Ok(labels.iter().position(|l| l == name).unwrap_or_else(|| {
        labels.push(name.to_owned());
        labels.len() - 1
    }))
}

fn next_char(text: &str, at: usize) -> usize {
    text[at..]
        .chars()
        .next()
        .map_or(at + 1, |c| at + c.len_utf8())
}

fn is_word(c: Option<char>) -> bool {
    c.is_some_and(char::is_alphanumeric)
}

/// Stops a deny-list term "Ann" from matching inside "Annual".
fn on_word_boundaries(text: &str, start: usize, end: usize) -> bool {
    let term = &text[start..end];
    let clear_left = !is_word(term.chars().next()) || !is_word(text[..start].chars().next_back());
    let clear_right = !is_word(term.chars().next_back()) || !is_word(text[end..].chars().next());
    clear_left && clear_right
}

impl Masker {
    pub fn new(config: &MaskerConfig) -> Result<Self, ConfigError> {
        let mut labels = Vec::new();
        let mut detectors = Vec::new();

        // Custom detectors come first so they win ties during the merge.
        for (name, pattern) in &config.custom_patterns {
            let label = label_of(&mut labels, name)?;
            let regex = Regex::new(pattern)
                .map_err(|e| ConfigError(format!("invalid pattern for {name}: {e}")))?;
            detectors.push(Detector {
                label,
                regex,
                validate: None,
                required_byte: None,
                value_group: false,
            });
        }

        let mut enabled = Vec::with_capacity(config.entities.len());
        for name in &config.entities {
            let known = ENTITIES.iter().find(|e| *e == name).ok_or_else(|| {
                ConfigError(format!(
                    "unknown entity {name:?}: expected one of {ENTITIES:?}"
                ))
            })?;
            enabled.push(*known);
        }
        for rule in rules::build(&enabled) {
            let label = label_of(&mut labels, rule.entity)?;
            detectors.push(Detector {
                label,
                regex: rule.regex,
                validate: rule.validate,
                required_byte: rule.required_byte,
                value_group: rule.value_group,
            });
        }

        let mut terms = Vec::new();
        let mut term_labels = Vec::new();
        for (name, group) in &config.deny_list {
            let label = label_of(&mut labels, name)?;
            for term in group {
                if term.is_empty() {
                    return Err(ConfigError(format!("empty deny-list term for {name}")));
                }
                terms.push(term.as_str());
                term_labels.push(label);
            }
        }
        let deny = if terms.is_empty() {
            None
        } else {
            let matcher = AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::Standard)
                .build(&terms)
                .map_err(|e| ConfigError(format!("invalid deny list: {e}")))?;
            Some(DenyList {
                matcher,
                labels: term_labels,
            })
        };

        let replacements = labels
            .iter()
            .map(|label| config.template.replace("{entity}", label))
            .collect();
        let allow = config.allow_list.iter().map(|s| s.to_lowercase()).collect();

        Ok(Self {
            labels,
            replacements,
            detectors,
            deny,
            allow,
        })
    }

    pub fn label(&self, span: &Span) -> &str {
        &self.labels[span.label]
    }

    /// Disjoint spans sorted by position.
    pub fn detect(&self, text: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        for detector in &self.detectors {
            detector.collect(text, &mut spans);
        }
        if let Some(deny) = &self.deny {
            deny.collect(text, &mut spans);
        }
        if !self.allow.is_empty() {
            spans.retain(|s| !self.allow.contains(&text[s.start..s.end].to_lowercase()));
        }
        merge(spans)
    }

    pub fn mask<'t>(&self, text: &'t str) -> Cow<'t, str> {
        let spans = self.detect(text);
        if spans.is_empty() {
            return Cow::Borrowed(text);
        }
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        for span in &spans {
            out.push_str(&text[cursor..span.start]);
            out.push_str(&self.replacements[span.label]);
            cursor = span.end;
        }
        out.push_str(&text[cursor..]);
        Cow::Owned(out)
    }

    /// Uses scoped threads rather than a global pool: a pool created before
    /// `fork()` hangs in the child, which is how Celery, gunicorn and
    /// `multiprocessing` commonly run Python workloads.
    pub fn mask_batch<'t>(&self, texts: &[&'t str]) -> Vec<Cow<'t, str>> {
        let workers = thread::available_parallelism().map_or(1, usize::from);
        let total_bytes: usize = texts.iter().map(|t| t.len()).sum();
        if workers == 1 || total_bytes < PARALLEL_MIN_BYTES {
            return texts.iter().map(|t| self.mask(t)).collect();
        }

        let mut out = vec![Cow::Borrowed(""); texts.len()];
        let chunks = Mutex::new(
            texts
                .chunks(BATCH_CHUNK_DOCS)
                .zip(out.chunks_mut(BATCH_CHUNK_DOCS)),
        );
        thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|_| {
                    scope.spawn(|| {
                        loop {
                            let next = chunks.lock().expect("no panics hold this lock").next();
                            let Some((input, output)) = next else { break };
                            for (text, slot) in input.iter().zip(output) {
                                *slot = self.mask(text);
                            }
                        }
                    })
                })
                .collect();
            // Joining here keeps `scope` from parking this thread. On Apple
            // platforms parking uses a libdispatch semaphore, and reusing one
            // after `fork()` kills the child.
            for handle in handles {
                handle.join().expect("workers do not panic");
            }
        });
        out
    }
}

impl Detector {
    fn collect(&self, text: &str, spans: &mut Vec<Span>) {
        if self
            .required_byte
            .is_some_and(|byte| memchr(byte, text.as_bytes()).is_none())
        {
            return;
        }
        let mut at = 0;
        loop {
            let found = if self.value_group {
                self.regex
                    .captures_at(text, at)
                    .and_then(|captures| captures.get(1))
            } else {
                self.regex.find_at(text, at)
            };
            let Some(m) = found else { break };
            if m.is_empty() {
                if m.end() >= text.len() {
                    break;
                }
                at = next_char(text, m.end());
                continue;
            }
            let accepted = match self.validate {
                Some(validate) => validate(text, m.start(), m.end()),
                None => Some(m.end()),
            };
            match accepted {
                Some(end) => {
                    spans.push(Span {
                        label: self.label,
                        start: m.start(),
                        end,
                    });
                    at = end;
                }
                // Resume just past the start, not the end: a rejected
                // candidate must not hide a real match overlapping it.
                None => at = next_char(text, m.start()),
            }
            if at >= text.len() {
                break;
            }
        }
    }
}

impl DenyList {
    fn collect(&self, text: &str, spans: &mut Vec<Span>) {
        for m in self.matcher.find_overlapping_iter(text) {
            if on_word_boundaries(text, m.start(), m.end()) {
                spans.push(Span {
                    label: self.labels[m.pattern().as_usize()],
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
    }
}

/// Overlapping hits become their union so no fragment of either is left in the
/// output. The merged span keeps the label of its longest member.
fn merge(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by_key(|s| (s.start, std::cmp::Reverse(s.end)));
    let mut merged: Vec<Span> = Vec::with_capacity(spans.len());
    let mut longest = 0;
    for span in spans {
        match merged.last_mut() {
            Some(last) if span.start < last.end => {
                last.end = last.end.max(span.end);
                if span.end - span.start > longest {
                    longest = span.end - span.start;
                    last.label = span.label;
                }
            }
            _ => {
                longest = span.end - span.start;
                merged.push(span);
            }
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masker() -> Masker {
        Masker::new(&MaskerConfig::default()).unwrap()
    }

    fn mask(text: &str) -> String {
        masker().mask(text).into_owned()
    }

    #[test]
    fn masks_each_builtin_entity() {
        let cases = [
            (
                "mail jane.doe+x@example.co.uk now",
                "mail [EMAIL_REDACTED] now",
            ),
            ("mail josé@exämple.com now", "mail [EMAIL_REDACTED] now"),
            ("call 555-123-4567.", "call [PHONE_REDACTED]."),
            ("call (415) 555-2671", "call [PHONE_REDACTED]"),
            ("call +1 (415) 555-2671", "call [PHONE_REDACTED]"),
            ("call +44 20 7946 0958", "call [PHONE_REDACTED]"),
            ("ssn 123-45-6789", "ssn [SSN_REDACTED]"),
            ("card 4111 1111 1111 1111", "card [CREDIT_CARD_REDACTED]"),
            ("card 378282246310005", "card [CREDIT_CARD_REDACTED]"),
            ("iban DE89 3704 0044 0532 0130 00", "iban [IBAN_REDACTED]"),
            ("from 192.168.1.1:80", "from [IP_ADDRESS_REDACTED]:80"),
            ("from 2001:db8::8a2e:370:7334", "from [IP_ADDRESS_REDACTED]"),
            ("key AKIAIOSFODNN7EXAMPLE", "key [API_KEY_REDACTED]"),
        ];
        for (input, expected) in cases {
            assert_eq!(mask(input), expected, "input: {input}");
        }
    }

    #[test]
    fn leaves_lookalikes_alone() {
        for text in [
            "000-12-3456",
            "666-12-3456",
            "900-12-3456",
            "4111 1111 1111 1112",
            "version 1.2.3.4.5",
            "abc::def",
            "at 12:30:45",
            "2023-10-15",
            "unix 1698765432",
            "isbn 978-3-16-148410-0",
            "version 10.0.19045.3803",
            "sku 7741-2291",
            "order ORD-48213907",
            "ticket 4111 1111 1111 1112",
            "password is required",
            "the id was lost",
            "Hello there",
            "stored on Google Drive",
            "Hi team",
            "no pii here",
            "",
        ] {
            assert_eq!(mask(text), text);
        }
    }

    #[test]
    fn labels_stay_readable_while_values_are_masked() {
        let cases = [
            ("Password: Zh-8", "Password: [PASSWORD_REDACTED]"),
            (
                "secured with password x9!kL",
                "secured with password [PASSWORD_REDACTED]",
            ),
            (
                "Account Number: 19359789181296",
                "Account Number: [ID_NUMBER_REDACTED]",
            ),
            ("Tax number 016-46-4431", "Tax number [SSN_REDACTED]"),
            (
                "Driver's License: M03IQ4682953",
                "Driver's License: [ID_NUMBER_REDACTED]",
            ),
            (
                "Date of Birth: 17/10/1944",
                "Date of Birth: [DATE_OF_BIRTH_REDACTED]",
            ),
            (
                "born on April 3rd, 1997",
                "born on [DATE_OF_BIRTH_REDACTED]",
            ),
            ("Username: kleppi1989", "Username: [USERNAME_REDACTED]"),
            ("Hi Neslihan,", "Hi [PERSON_REDACTED],"),
            (
                "seen by Dr. Le Grand today",
                "seen by Dr. [PERSON_REDACTED] today",
            ),
            ("City: Tempe, AZ", "City: [ADDRESS_REDACTED], AZ"),
            ("ZIP Code: 08501-1312", "ZIP Code: [ADDRESS_REDACTED]"),
        ];
        for (input, expected) in cases {
            assert_eq!(mask(input), expected, "input: {input}");
        }
    }

    #[test]
    fn masks_addresses_and_other_phone_formats() {
        let cases = [
            ("at 1669 Moxby Lane now", "at [ADDRESS_REDACTED] now"),
            ("by Pine Mountain Road", "by [ADDRESS_REDACTED]"),
            ("near SY13 2RN today", "near [ADDRESS_REDACTED] today"),
            ("ring 020 7183 1234 now", "ring [PHONE_REDACTED] now"),
            ("ring 0174-510 950 3970", "ring [PHONE_REDACTED]"),
            ("ring +119.73 420 4571", "ring [PHONE_REDACTED]"),
            ("ssn 510.73.1875", "ssn [SSN_REDACTED]"),
        ];
        for (input, expected) in cases {
            assert_eq!(mask(input), expected, "input: {input}");
        }
    }

    #[test]
    fn iban_does_not_swallow_the_next_word() {
        assert_eq!(
            mask("to DE89 3704 0044 0532 0130 00 BANK"),
            "to [IBAN_REDACTED] BANK"
        );
    }

    #[test]
    fn rejected_candidate_does_not_hide_overlapping_match() {
        // "AB12" opens an IBAN candidate that fails its checksum. The real IBAN
        // starts inside that candidate, so scanning must resume within it.
        assert_eq!(
            mask("ref AB12 DE89 3704 0044 0532 0130 00"),
            "ref AB12 [IBAN_REDACTED]"
        );
    }

    #[test]
    fn private_key_is_masked_even_when_truncated() {
        assert_eq!(
            mask("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\ndone"),
            "[PRIVATE_KEY_REDACTED]\ndone"
        );
        assert_eq!(
            mask("x -----BEGIN PRIVATE KEY-----\nabc"),
            "x [PRIVATE_KEY_REDACTED]"
        );
    }

    #[test]
    fn overlaps_merge_instead_of_leaking_fragments() {
        let config = MaskerConfig {
            custom_patterns: vec![("TAG".into(), r"doe@example".into())],
            ..MaskerConfig::default()
        };
        let masked = Masker::new(&config)
            .unwrap()
            .mask("jane.doe@example.com")
            .into_owned();
        assert_eq!(masked, "[EMAIL_REDACTED]");
    }

    #[test]
    fn deny_list_respects_word_boundaries_and_case() {
        let config = MaskerConfig {
            deny_list: vec![("PERSON".into(), vec!["Ann".into()])],
            ..MaskerConfig::default()
        };
        let m = Masker::new(&config).unwrap();
        assert_eq!(
            m.mask("ask ANN about Annual"),
            "ask [PERSON_REDACTED] about Annual"
        );
    }

    #[test]
    fn allow_list_exempts_exact_values() {
        let config = MaskerConfig {
            allow_list: vec!["Support@Acme.com".into()],
            ..MaskerConfig::default()
        };
        let m = Masker::new(&config).unwrap();
        assert_eq!(
            m.mask("support@acme.com or a@b.io"),
            "support@acme.com or [EMAIL_REDACTED]"
        );
    }

    #[test]
    fn zero_width_custom_patterns_terminate() {
        let config = MaskerConfig {
            entities: Vec::new(),
            custom_patterns: vec![("X".into(), "a*".into())],
            ..MaskerConfig::default()
        };
        assert_eq!(
            Masker::new(&config).unwrap().mask("bébaa"),
            "béb[X_REDACTED]"
        );
    }

    #[test]
    fn batch_matches_sequential_across_the_parallel_threshold() {
        let m = masker();
        let doc = "x".repeat(4096) + " a@b.io";
        let texts: Vec<&str> = std::iter::repeat_n(doc.as_str(), 256).collect();
        let out = m.mask_batch(&texts);
        assert!(out.iter().all(|t| *t == m.mask(&doc)));
    }

    #[test]
    fn rejects_bad_config() {
        let bad = [
            MaskerConfig {
                entities: vec!["NOPE".into()],
                ..MaskerConfig::default()
            },
            MaskerConfig {
                custom_patterns: vec![("X".into(), "(".into())],
                ..MaskerConfig::default()
            },
            MaskerConfig {
                custom_patterns: vec![("lower".into(), "a".into())],
                ..MaskerConfig::default()
            },
            MaskerConfig {
                deny_list: vec![("X".into(), vec![String::new()])],
                ..MaskerConfig::default()
            },
        ];
        for config in &bad {
            assert!(Masker::new(config).is_err());
        }
    }
}
