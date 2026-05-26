pub fn parse_device_label(args: &[String]) -> Option<&str> {
    parse_option_value(args, "--device-label")
}

pub fn parse_conversation_label(args: &[String]) -> Option<&str> {
    parse_option_value(args, "--conversation-label")
}

pub fn parse_member_keypackage_path(args: &[String]) -> Option<&str> {
    parse_option_value(args, "--member-keypackage")
}

pub fn parse_welcome_artifact_path(args: &[String]) -> Option<&str> {
    parse_option_value(args, "--welcome")
}

pub fn parse_plaintext(args: &[String]) -> Option<&str> {
    parse_option_value(args, "--plaintext")
}

pub fn parse_message_artifact_path(args: &[String]) -> Option<&str> {
    parse_option_value(args, "--message")
}

pub fn parse_message_label(args: &[String]) -> Option<&str> {
    parse_option_value(args, "--message-label")
}

pub fn parse_write_artifact_flag(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--write-artifact")
}

fn parse_option_value<'a>(args: &'a [String], option_name: &str) -> Option<&'a str> {
    let mut index = 0;

    while index < args.len() {
        if args[index] == option_name {
            return args.get(index + 1).map(String::as_str);
        }

        index += 1;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_device_label_argument() {
        let args = vec![
            "--device-label".to_string(),
            "carbonstack-alice-device".to_string(),
        ];

        assert_eq!(parse_device_label(&args), Some("carbonstack-alice-device"));
    }

    #[test]
    fn missing_device_label_argument_returns_none() {
        let args = vec!["--other".to_string(), "value".to_string()];
        assert_eq!(parse_device_label(&args), None);
    }

    #[test]
    fn detects_write_artifact_flag() {
        let args = vec!["--write-artifact".to_string()];
        assert!(parse_write_artifact_flag(&args));
    }

    #[test]
    fn missing_write_artifact_flag_is_false() {
        let args = vec![
            "--device-label".to_string(),
            "carbonstack-bob-device".to_string(),
        ];
        assert!(!parse_write_artifact_flag(&args));
    }
}
