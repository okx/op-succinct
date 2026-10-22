//! Pure classifier: decide whether a protected item's raw value is plaintext, a
//! well-formed reference, or a malformed reference.

/// Outcome of classifying a protected item's non-empty raw value.
#[derive(Debug)]
pub(crate) enum Classification {
    /// A plaintext value; must be left byte-identical.
    Plaintext,
    /// A well-formed reference. `key` is the verbatim remainder after the prefix.
    KmsRef { key: String },
    /// The prefix was present but the key part was empty — a format error.
    InvalidFormat,
}

/// Classify a non-empty protected value.
///
/// A value is a reference iff it begins with the exact bytes `kms:` (lowercase,
/// case-sensitive) and the remainder is non-empty; the remainder is the key,
/// used verbatim (no trimming or normalization). `kms:` with an empty remainder
/// is a format error. Anything else — including `KMS:`/`Kms:`, a raw hex key, a
/// raw ARN, or a node-list string — is plaintext.
pub(crate) fn classify(value: &str) -> Classification {
    match value.strip_prefix("kms:") {
        Some("") => Classification::InvalidFormat,
        Some(key) => Classification::KmsRef { key: key.to_string() },
        None => Classification::Plaintext,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_hex_is_plaintext() {
        assert!(matches!(classify("0xabc123"), Classification::Plaintext));
    }

    #[test]
    fn valid_ref_extracts_verbatim_key() {
        assert!(matches!(
            classify("kms:prod/network-key"),
            Classification::KmsRef { key } if key == "prod/network-key"
        ));
    }

    #[test]
    fn empty_key_is_invalid_format() {
        assert!(matches!(classify("kms:"), Classification::InvalidFormat));
    }

    #[test]
    fn uppercase_prefix_is_plaintext() {
        assert!(matches!(classify("KMS:key"), Classification::Plaintext));
    }

    #[test]
    fn mixedcase_prefix_is_plaintext() {
        assert!(matches!(classify("Kms:key"), Classification::Plaintext));
    }

    #[test]
    fn key_is_not_trimmed() {
        assert!(matches!(
            classify("kms: spaced"),
            Classification::KmsRef { key } if key == " spaced"
        ));
    }
}
