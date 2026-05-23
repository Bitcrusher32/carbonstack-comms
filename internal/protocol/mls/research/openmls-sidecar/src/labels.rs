pub fn validate_device_label(label: &str) -> Result<(), String> {
    if label.is_empty() {
        return Err("device label is required".to_string());
    }

    if label == "." || label == ".." {
        return Err("device label cannot be . or ..".to_string());
    }

    if label.len() > 96 {
        return Err("device label is too long".to_string());
    }

    for ch in label.chars() {
        let allowed = ch.is_ascii_alphanumeric() || ch == '-' || ch == '_';

        if !allowed {
            return Err(format!(
                "device label contains unsupported character: {ch:?}"
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_safe_device_labels() {
        let labels = [
            "carbonstack-alice-device",
            "carbonstack_bob_device",
            "AliceDevice01",
            "device-123_test",
        ];

        for label in labels {
            validate_device_label(label).expect("safe label should validate");
        }
    }

    #[test]
    fn rejects_empty_device_label() {
        let err = validate_device_label("").expect_err("empty label should fail");
        assert!(err.contains("required"));
    }

    #[test]
    fn rejects_dot_device_labels() {
        validate_device_label(".").expect_err("dot label should fail");
        validate_device_label("..").expect_err("dot-dot label should fail");
    }

    #[test]
    fn rejects_path_separators_and_spaces() {
        let labels = [
            "alice/device",
            "alice\\device",
            "alice device",
            "../alice",
            ".\\alice",
        ];

        for label in labels {
            validate_device_label(label).expect_err("unsafe label should fail");
        }
    }

    #[test]
    fn rejects_overlong_device_label() {
        let label = "a".repeat(97);
        let err = validate_device_label(&label).expect_err("overlong label should fail");
        assert!(err.contains("too long"));
    }
}
