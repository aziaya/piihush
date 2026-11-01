//! Built-in detectors: one regex plus an optional validator per rule.
//!
//! Word boundaries are ASCII-only (`(?-u)`) because Unicode `\b` disables the
//! regex crate's lazy DFA, which is what makes these patterns fast.

use std::net::Ipv6Addr;

use regex::Regex;

/// Checks a candidate at `text[start..end]`, returning the end of the accepted
/// match (it may shrink the candidate) or `None` to reject it.
pub type Validator = fn(&str, usize, usize) -> Option<usize>;

pub const ENTITIES: &[&str] = &[
    "EMAIL",
    "PHONE",
    "SSN",
    "CREDIT_CARD",
    "IBAN",
    "IP_ADDRESS",
    "API_KEY",
    "JWT",
    "PRIVATE_KEY",
    "ID_NUMBER",
    "PASSWORD",
    "DATE_OF_BIRTH",
    "ADDRESS",
    "PERSON",
    "USERNAME",
];

pub struct Rule {
    pub entity: &'static str,
    pub regex: Regex,
    pub validate: Option<Validator>,
    /// A byte every match must contain, used to skip the regex entirely.
    pub required_byte: Option<u8>,
    /// Mask capture group 1 rather than the whole match, keeping labels such
    /// as "Password:" readable.
    pub value_group: bool,
}

type RuleSpec = (&'static str, &'static str, Option<Validator>, Option<u8>);

const EMAIL: &str = r"[\p{L}\p{N}._%+'-]+@[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)*\.\p{L}{2,}";
const SSN: &str = r"(?-u)\b[0-9]{3}(?:-[0-9]{2}-|\x20[0-9]{2}\x20|\.[0-9]{2}\.)[0-9]{4}\b";
const PHONE_NANP: &str = r"(?-u)(?:\+?1[-.\x20]?)?(?:\([2-9][0-9]{2}\)[-.\x20]?|[2-9][0-9]{2}[-.\x20]?)[0-9]{3}[-.\x20]?[0-9]{4}";
const PHONE_INTL: &str = r"(?-u)\+[1-9](?:[-.\x20()]{0,2}[0-9]){6,14}";
const PHONE_GENERAL: &str = r"(?-u)(?:\+|\b)[0-9][-.\x20()0-9]{7,22}[0-9]\b";
const CREDIT_CARD: &str = concat!(
    r"(?-u)\b(?:",
    r"(?:4[0-9]{3}|5[1-5][0-9]{2}|2[2-7][0-9]{2}|6011|6[25][0-9]{2}|35[0-9]{2})",
    r"(?:[-\x20]?[0-9]{4}){3}",
    r"|3[47][0-9]{2}[-\x20]?[0-9]{6}[-\x20]?[0-9]{5}",
    r"|3(?:0[0-5]|[68][0-9])[0-9][-\x20]?[0-9]{6}[-\x20]?[0-9]{4}",
    r")\b",
);
const IBAN: &str =
    r"(?i-u)\b[A-Z]{2}[0-9]{2}(?:[-\x20]?[A-Z0-9]{4}){2,7}(?:[-\x20]?[A-Z0-9]{1,3})?\b";
const IPV4: &str =
    r"(?-u)\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\b";
const IPV6: &str = r"(?i-u)(?:[0-9a-f]{0,4}:){2,7}(?:[0-9a-f]{1,4}|:)?";
const API_KEY: &str = concat!(
    r"(?-u)\b(?:",
    r"(?:AKIA|ASIA)[A-Z0-9]{16}",              // AWS
    r"|gh[pousr]_[A-Za-z0-9]{36,}",            // GitHub
    r"|github_pat_[A-Za-z0-9_]{22,}",          // GitHub fine-grained
    r"|glpat-[A-Za-z0-9_-]{20,}",              // GitLab
    r"|xox[abeoprs]-[A-Za-z0-9-]{10,}",        // Slack
    r"|[srp]k_(?:live|test)_[A-Za-z0-9]{16,}", // Stripe
    r"|AIza[A-Za-z0-9_-]{35}",                 // Google
    r"|sk-[A-Za-z0-9_-]{20,}",                 // OpenAI, Anthropic and similar
    r"|hf_[A-Za-z0-9]{30,}",                   // Hugging Face
    r"|npm_[A-Za-z0-9]{36}",                   // npm
    r"|pypi-[A-Za-z0-9_-]{50,}",               // PyPI
    r")",
);
const JWT: &str = r"(?-u)\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}";
// An unterminated key runs to the end of the text so a chunk boundary inside
// the key cannot leave its body exposed.
const PRIVATE_KEY: &str =
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?s:.*?)(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)";

const SPECS: &[RuleSpec] = &[
    ("PRIVATE_KEY", PRIVATE_KEY, None, None),
    ("JWT", JWT, None, None),
    ("API_KEY", API_KEY, None, None),
    ("EMAIL", EMAIL, None, Some(b'@')),
    ("CREDIT_CARD", CREDIT_CARD, Some(valid_card), None),
    ("IBAN", IBAN, Some(valid_iban), None),
    ("SSN", SSN, Some(valid_ssn), None),
    ("PHONE", PHONE_NANP, Some(digit_isolated), None),
    ("PHONE", PHONE_INTL, Some(valid_intl_phone), Some(b'+')),
    ("IP_ADDRESS", IPV4, Some(valid_ipv4), Some(b'.')),
    ("IP_ADDRESS", IPV6, Some(valid_ipv6), Some(b':')),
    ("PHONE", PHONE_GENERAL, Some(valid_general_phone), None),
    ("ADDRESS", STREET_NUMBERED, None, None),
    ("ADDRESS", STREET_NAMED, None, None),
    ("ADDRESS", UK_POSTCODE, None, None),
    ("ADDRESS", ZIP_PLUS_4, None, Some(b'-')),
];

// Everything below needs a nearby label: the value alone has no reliable
// shape. Capture group 1 is the value that gets masked.
macro_rules! name {
    () => {
        r"\p{Lu}[\p{L}'-]+(?:\s+\p{Lu}[\p{L}'-]+){0,2}"
    };
}
const ID_LABELLED: &str = concat!(
    r"(?i-u:\b(?:account|acct|passport|licen[cs]e|social\s+security|social|security|ssn|sin|tin",
    r"|tax|card|routing|member|policy|id|identification|payment\s+(?:via|with|by|through|using)",
    r"|paid\s+(?:via|with|by)|identified\s+by)(?:\s+(?:number|numbers|num|no\.?|id|code|card|label))*)",
    r#"[\s:=#.'’"-]{0,4}(?:is\s+|of\s+)?"#,
    r"([A-Z0-9][A-Z0-9.-]*(?:\x20[A-Z0-9][A-Z0-9.-]*){0,3})(?-u:\b)",
);
const PASSWORD_SEPARATED: &str = r#"(?i-u:\b(?:password|passwd|pwd|passphrase|passcode|access\s+code|pin))\s*[:=]\s*['"]?(\S{3,})"#;
const PASSWORD_INLINE: &str = concat!(
    r"(?i-u:\b(?:password|passwd|passphrase|passcode))(?:\s+is)?\s+",
    r"(\S*[0-9!@#$%^&*(){}\[\]<>~`|\\/?]\S*)",
);
const DATE_OF_BIRTH: &str = concat!(
    r"(?i-u:\b(?:dob|d\.o\.b\.?|date\s+of\s+birth|birth\s?date|birthday|born(?:\s+on)?))[\s:=-]*(",
    r"[0-9]{1,4}[-/.][0-9]{1,2}[-/.][0-9]{1,4}(?:T[0-9:]+)?",
    r"|[A-Za-z]{3,9}\.?\s[0-9]{1,2}(?:st|nd|rd|th)?,?\s[0-9]{4}",
    r"|[0-9]{1,2}(?:st|nd|rd|th)?\s(?:of\s)?[A-Za-z]{3,9},?\s[0-9]{4}",
    r")",
);
const STREET_NUMBERED: &str = concat!(
    r"(?-u)\b[0-9]{1,6}[A-Za-z]?\x20(?:[A-Z][a-z'-]+\x20){1,3}",
    r"(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Boulevard|Blvd|Court|Ct|Way|Place|Pl",
    r"|Terrace|Circle|Close|Crescent|Highway|Hwy|Parkway|Square|Trail|Row|Walk|Grove)\b",
);
const STREET_NAMED: &str = concat!(
    r"(?-u)\b(?:[A-Z][a-z'-]+\x20){1,3}",
    r"(?:Street|Road|Lane|Avenue|Boulevard|Terrace|Crescent|Highway|Parkway|Grove)\b",
);
const UK_POSTCODE: &str = r"(?-u)\b[A-Z]{1,2}[0-9][A-Z0-9]?\x20[0-9][A-Z]{2}\b";
const ZIP_PLUS_4: &str = r"(?-u)\b[0-9]{5}-[0-9]{4}\b";
const ADDRESS_LABELLED: &str = concat!(
    r"(?i-u:\b(?:street\s+address|home\s+address|address|street|city|town|location))\s*:\s*",
    r"([^\s<,;][^\n<,;]{1,59})",
);
const ZIP_LABELLED: &str = r"(?i-u:\b(?:zip(?:\s?code)?|post(?:al)?\s?code))[\s:=#]*([A-Z0-9][A-Z0-9\x20-]{2,9}[A-Z0-9])(?-u:\b)";
const CITY_CONTEXT: &str = concat!(
    r"(?-u:\b)(?:residing|living|lives|resides|located|based)\s+(?:in|at)\s+",
    r"((?:[0-9]+\s+)?\p{Lu}[\p{L}'-]+(?:\s+\p{Lu}[\p{L}'-]+){0,3})",
);
const USERNAME: &str =
    r"(?i-u:\b(?:username|user\s+name|user\s?id|login|handle))\s*(?:is\s+|[:=]\s*)(\S{3,})";
const PERSON_TITLE: &str = concat!(
    r"(?-u:\b)(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Mstr|Sir|Madam)\.?\s+(",
    name!(),
    r")"
);
const PERSON_GREETING: &str = concat!(
    r"(?i-u:\b(?:hi|hey|hello|dear|good\s+(?:morning|afternoon|evening)|greetings)),?\s+(",
    name!(),
    r"|[a-z0-9._-]*[0-9][a-z0-9._-]*)"
);
const PERSON_LABELLED: &str = concat!(
    r"(?i-u:\b(?:name|full\s+name|given\s+name|first\s+name|last\s+name|surname|patient|borrower",
    r"|child|student|contact\s+person|employee|customer|client|applicant|sincerely|regards|signed))",
    r"\s*[:,]\s*(",
    name!(),
    r")"
);

const CONTEXT_SPECS: &[(&str, &str, Option<Validator>)] = &[
    ("ID_NUMBER", ID_LABELLED, Some(enough_digits)),
    ("PASSWORD", PASSWORD_SEPARATED, None),
    ("PASSWORD", PASSWORD_INLINE, None),
    ("DATE_OF_BIRTH", DATE_OF_BIRTH, None),
    ("ADDRESS", ADDRESS_LABELLED, None),
    ("ADDRESS", ZIP_LABELLED, None),
    ("ADDRESS", CITY_CONTEXT, None),
    ("USERNAME", USERNAME, None),
    ("PERSON", PERSON_TITLE, None),
    ("PERSON", PERSON_GREETING, None),
    ("PERSON", PERSON_LABELLED, None),
];

pub fn build(enabled: &[&str]) -> Vec<Rule> {
    let plain = SPECS
        .iter()
        .map(|&(entity, pattern, validate, required_byte)| {
            (entity, pattern, validate, required_byte, false)
        });
    let contextual = CONTEXT_SPECS
        .iter()
        .map(|&(entity, pattern, validate)| (entity, pattern, validate, None, true));
    plain
        .chain(contextual)
        .filter(|(entity, ..)| enabled.contains(entity))
        .map(
            |(entity, pattern, validate, required_byte, value_group)| Rule {
                entity,
                regex: Regex::new(pattern).expect("built-in patterns are valid"),
                validate,
                required_byte,
                value_group,
            },
        )
        .collect()
}

fn digits(text: &str) -> impl Iterator<Item = u32> + '_ {
    text.bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| u32::from(b - b'0'))
}

fn valid_ssn(text: &str, start: usize, end: usize) -> Option<usize> {
    let d: Vec<u32> = digits(&text[start..end]).collect();
    let area = d[0] * 100 + d[1] * 10 + d[2];
    let group = d[3] * 10 + d[4];
    let serial = d[5..].iter().fold(0, |acc, x| acc * 10 + x);
    (area != 0 && area != 666 && area < 900 && group != 0 && serial != 0).then_some(end)
}

fn valid_card(text: &str, start: usize, end: usize) -> Option<usize> {
    let d: Vec<u32> = digits(&text[start..end]).collect();
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| match (i % 2, x * 2) {
            (0, _) => x,
            (_, doubled) if doubled > 9 => doubled - 9,
            (_, doubled) => doubled,
        })
        .sum();
    (sum.is_multiple_of(10) && d.iter().any(|&x| x != d[0])).then_some(end)
}

fn iban_checksum_ok(candidate: &str) -> bool {
    let compact: Vec<u8> = candidate
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if !(15..=34).contains(&compact.len()) {
        return false;
    }
    let (head, tail) = compact.split_at(4);
    let remainder = tail.iter().chain(head).fold(0u32, |acc, &b| match b {
        b'0'..=b'9' => (acc * 10 + u32::from(b - b'0')) % 97,
        _ => (acc * 100 + u32::from(b - b'A') + 10) % 97,
    });
    remainder == 1
}

/// The pattern may swallow a following word ("... 00 BANK"), so walk the end
/// back until the checksum holds.
fn valid_iban(text: &str, start: usize, end: usize) -> Option<usize> {
    (start + 15..=end)
        .rev()
        .filter(|&e| text.as_bytes()[e - 1].is_ascii_alphanumeric())
        .find(|&e| iban_checksum_ok(&text[start..e]))
}

fn digit_isolated(text: &str, start: usize, end: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let before = start.checked_sub(1).map(|i| bytes[i]);
    let after = bytes.get(end).copied();
    let digit_adjacent = |b: Option<u8>| b.is_some_and(|b| b.is_ascii_digit());
    (!digit_adjacent(before) && !digit_adjacent(after)).then_some(end)
}

fn valid_intl_phone(text: &str, start: usize, end: usize) -> Option<usize> {
    let count = digits(&text[start..end]).count();
    digit_isolated(text, start, end).filter(|_| (8..=15).contains(&count))
}

/// Catches numbers outside the US formats. Without a `+` or separators a long
/// number is more likely an ID or timestamp than a phone.
fn valid_general_phone(text: &str, start: usize, end: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let candidate = &text[start..end];
    let count = digits(candidate).count();
    let plus = candidate.starts_with('+');
    let separators: Vec<u8> = candidate
        .bytes()
        .filter(|b| !b.is_ascii_digit() && *b != b'+')
        .collect();
    let dotted_only = !separators.is_empty() && separators.iter().all(|&b| b == b'.');
    let isbn = count == 13 && (candidate.starts_with("978") || candidate.starts_with("979"));
    // 3-2-4 and 5-4 groupings are SSNs and ZIP+4 codes, not phone numbers.
    let groups: Vec<usize> = candidate
        .split(|c: char| !c.is_ascii_digit())
        .filter(|group| !group.is_empty())
        .map(str::len)
        .collect();
    let other_format = matches!(groups.as_slice(), [3, 2, 4] | [5, 4]);
    // A tail of a longer run, such as the end of a failed card number.
    let continues_run = start >= 2
        && matches!(bytes[start - 1], b' ' | b'-' | b'.')
        && bytes[start - 2].is_ascii_digit();
    let plausible = (9..=15).contains(&count)
        && (plus || !separators.is_empty())
        && (plus || !dotted_only)
        && !isbn
        && !other_format
        && !continues_run;
    digit_isolated(text, start, end).filter(|_| plausible)
}

fn enough_digits(text: &str, start: usize, end: usize) -> Option<usize> {
    (digits(&text[start..end]).count() >= 4).then_some(end)
}

/// Rejects dotted runs such as version strings ("1.2.3.4.5").
fn valid_ipv4(text: &str, start: usize, end: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let dotted_before = start >= 2 && bytes[start - 1] == b'.' && bytes[start - 2].is_ascii_digit();
    let dotted_after =
        bytes.get(end) == Some(&b'.') && bytes.get(end + 1).is_some_and(|b| b.is_ascii_digit());
    (!dotted_before && !dotted_after).then_some(end)
}

/// Requires a digit so C++/Rust paths such as `abc::def` are left alone.
fn valid_ipv6(text: &str, start: usize, end: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let hex_adjacent = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_alphanumeric());
    let before = start.checked_sub(1).and_then(|i| bytes.get(i));
    let candidate = &text[start..end];
    (!hex_adjacent(before)
        && !hex_adjacent(bytes.get(end))
        && digits(candidate).next().is_some()
        && candidate.parse::<Ipv6Addr>().is_ok())
    .then_some(end)
}
