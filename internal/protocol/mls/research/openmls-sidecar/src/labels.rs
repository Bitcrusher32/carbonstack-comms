pub fn validate_device_label(label: &str) -> Result<(), String> {
    validate_safe_label(label, "device")
}

pub fn validate_conversation_label(label: &str) -> Result<(), String> {
    validate_safe_label(label, "conversation")
}

fn validate_safe_label(label: &str, kind: &str) -> Result<(), String> {
    if label.is_empty() {
        return Err(format!("{kind} label is required"));
    }

    if label == "." || label == ".." {
        return Err(format!("{kind} label cannot be . or .."));
    }

    if label.len() > 96 {
        return Err(format!("{kind} label is too long"));
    }

    for ch in label.chars() {
        let allowed = ch.is_ascii_alphanumeric() || ch == '-' || ch == '_';

        if !allowed {
            return Err(format!(
                "{kind} label contains unsupported character: {ch:?}"
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

    #[test]
    fn accepts_safe_conversation_labels() {
        let labels = [
            "carbonstack-test-conversation",
            "test_conversation_01",
            "Conversation01",
            "conversation-123_test",
        ];

        for label in labels {
            validate_conversation_label(label).expect("safe conversation label should validate");
        }
    }

    #[test]
    fn rejects_empty_conversation_label() {
        let err =
            validate_conversation_label("").expect_err("empty conversation label should fail");
        assert!(err.contains("required"));
    }

    #[test]
    fn rejects_dot_conversation_labels() {
        validate_conversation_label(".").expect_err("dot label should fail");
        validate_conversation_label("..").expect_err("dot-dot label should fail");
    }

    #[test]
    fn rejects_conversation_path_separators_dots_and_spaces() {
        let labels = [
            "test/conversation",
            "test\\conversation",
            "test conversation",
            "../test",
            ".\\test",
            "test.conversation",
        ];

        for label in labels {
            validate_conversation_label(label).expect_err("unsafe conversation label should fail");
        }
    }

    #[test]
    fn rejects_overlong_conversation_label() {
        let label = "a".repeat(97);
        let err = validate_conversation_label(&label)
            .expect_err("overlong conversation label should fail");
        assert!(err.contains("too long"));
    }
}
