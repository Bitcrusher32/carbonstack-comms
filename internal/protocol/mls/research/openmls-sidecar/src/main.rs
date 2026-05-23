mod labels;
mod state;

use labels::validate_device_label;
use state::{IdentityCreateResult, create_dev_identity, device_state_dir};
use std::env;
use std::io;

const PROVIDER_NAME: &str = "openmls";
const IMPLEMENTATION: &str = "carbonstack-openmls-sidecar";
const MODE: &str = "experimental-sidecar";
const PHASE_PROVIDER_INFO: &str = "phase2d-provider-info";
const PHASE_IDENTITY_CREATE: &str = "phase2d-identity-create-dev";

const WARNINGS: [&str; 4] = [
    "OpenMLS is not wired into CarbonStackComms",
    "Cypher does not route MLS payloads",
    "trust-state storage does not consume provider events",
    "identity-create writes dev-only secret-bearing signer state but never prints private material",
];

const UNSUPPORTED_COMMANDS: [&str; 8] = [
    "public-bundle-export",
    "conversation-create",
    "conversation-add-member",
    "conversation-join",
    "message-protect",
    "message-open",
    "state-checkpoint",
    "state-load-check",
];

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("provider-info") => print_provider_info(),
        Some("identity-create") => handle_identity_create(&args[2..]),
        Some("--help") | Some("-h") | None => print_help(),
        Some(other) => {
            print_unsupported_command(other);
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!("CarbonStack OpenMLS sidecar");
    println!("Status: experimental Phase 2D provider boundary prototype");
    println!();
    println!("Supported commands:");
    println!("  provider-info");
    println!(
        "  identity-create --device-label <label>   (recognized, validates label, not implemented)"
    );
    println!();
    println!("Unsupported intentionally:");
    for command in UNSUPPORTED_COMMANDS {
        println!("  {command}");
    }
}

fn handle_identity_create(args: &[String]) {
    let Some(device_label) = parse_device_label(args) else {
        print_identity_create_missing_label();
        std::process::exit(2);
    };

    if let Err(reason) = validate_device_label(device_label) {
        print_identity_create_invalid_label(device_label, &reason);
        std::process::exit(2);
    }

    match create_dev_identity(device_label) {
        Ok(result) => {
            print_identity_create_success(&result);
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            print_identity_create_already_exists(device_label);
            std::process::exit(3);
        }
        Err(err) => {
            print_identity_create_state_write_failed(device_label, &err.to_string());
            std::process::exit(4);
        }
    }
}
fn parse_device_label(args: &[String]) -> Option<&str> {
    let mut index = 0;

    while index < args.len() {
        if args[index] == "--device-label" {
            return args.get(index + 1).map(String::as_str);
        }

        index += 1;
    }

    None
}

fn print_provider_info() {
    println!(
        r#"{{
  "ok": true,
  "command": "provider-info",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "data": {{
    "capabilities": [
      "provider-info",
      "identity-create"
    ],
    "unsupported": [
      "public-bundle-export",
      "conversation-create",
      "conversation-add-member",
      "conversation-join",
      "message-protect",
      "message-open",
      "state-checkpoint",
      "state-load-check"
    ],
    "security_level": "experimental; not production E2EE"
  }},
  "events": [],
  "warnings": [
    "{warning0}",
    "{warning1}",
    "{warning2}",
    "{warning3}",
    "identity-create writes dev-only OpenMLS identity material locally but does not print private material"
  ],
  "private_material_included": false
}}"#,
        provider = PROVIDER_NAME,
        implementation = IMPLEMENTATION,
        mode = MODE,
        phase = PHASE_PROVIDER_INFO,
        warning0 = WARNINGS[0],
        warning1 = WARNINGS[1],
        warning2 = WARNINGS[2],
        warning3 = WARNINGS[3],
    );
}

fn print_unsupported_command(command: &str) {
    println!(
        r#"{{
  "ok": false,
  "command": "{command}",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "unsupported_command",
    "message": "unsupported command: {command}",
    "provider_event": "provider.command.unsupported",
    "severity": "warning",
    "trust_relevant": false
  }},
  "events": [
    {{
      "event": "provider.command.unsupported",
      "severity": "warning",
      "trust_relevant": false
    }}
  ],
  "warnings": [],
  "private_material_included": false
}}"#,
        command = json_escape(command),
        provider = PROVIDER_NAME,
        implementation = IMPLEMENTATION,
        mode = MODE,
        phase = PHASE_PROVIDER_INFO,
    );
}

fn print_identity_create_missing_label() {
    println!(
        r#"{{
  "ok": false,
  "command": "identity-create",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "missing_required_argument",
    "message": "identity-create requires --device-label <label>",
    "provider_event": "provider.command.invalid",
    "severity": "warning",
    "trust_relevant": false
  }},
  "events": [
    {{
      "event": "provider.command.invalid",
      "severity": "warning",
      "trust_relevant": false
    }}
  ],
  "warnings": [],
  "private_material_included": false
}}"#,
        provider = PROVIDER_NAME,
        implementation = IMPLEMENTATION,
        mode = MODE,
        phase = PHASE_IDENTITY_CREATE,
    );
}

fn print_identity_create_invalid_label(device_label: &str, reason: &str) {
    println!(
        r#"{{
  "ok": false,
  "command": "identity-create",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "invalid_device_label",
    "message": "invalid device label: {reason}",
    "provider_event": "provider.command.invalid",
    "severity": "warning",
    "trust_relevant": false
  }},
  "events": [
    {{
      "event": "provider.command.invalid",
      "severity": "warning",
      "trust_relevant": false
    }}
  ],
  "warnings": [],
  "private_material_included": false,
  "data": {{
    "device_label": "{device_label}"
  }}
}}"#,
        provider = PROVIDER_NAME,
        implementation = IMPLEMENTATION,
        mode = MODE,
        phase = PHASE_IDENTITY_CREATE,
        reason = json_escape(reason),
        device_label = json_escape(device_label),
    );
}

fn print_identity_create_success(result: &IdentityCreateResult) {
    let envelope = serde_json::json!({
        "ok": true,
        "command": "identity-create",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": PHASE_IDENTITY_CREATE,
        "data": {
            "device_label": result.device_label,
            "identity_created": true,
            "state_written": true,
            "state_scope": "dev-local-sidecar-state",
            "state_path_hint": result.state_dir.to_string_lossy(),
            "prep_manifest_path_hint": result.prep_manifest_path.to_string_lossy(),
            "identity_summary_path_hint": result.identity_summary_path.to_string_lossy(),
            "identity_state_path_hint": result.identity_state_path.to_string_lossy(),
            "signer_path_hint": result.signer_path.to_string_lossy(),
            "public_identity_ref": result.public_identity_ref,
            "public_signature_key_len": result.public_signature_key_len,
            "provider_storage_written": false,
            "public_bundle_available": false
        },
        "events": [
            {
                "event": "provider.identity.created",
                "severity": "notice",
                "trust_relevant": false
            }
        ],
        "warnings": [
            "dev-only identity material; not production secure storage",
            "private material was written locally but not printed",
            "OpenMLS is not wired into CarbonStackComms",
            "public bundle export is not implemented"
        ],
        "private_material_included": false
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope)
            .expect("failed to serialize identity-create success envelope")
    );
}
fn print_identity_create_already_exists(device_label: &str) {
    let state_dir = device_state_dir(device_label);
    let state_dir_hint = state_dir.to_string_lossy();

    println!(
        r#"{{
  "ok": false,
  "command": "identity-create",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "identity_already_exists",
    "message": "identity state already exists; refusing overwrite",
    "provider_event": "provider.identity.exists",
    "severity": "warning",
    "trust_relevant": false
  }},
  "events": [
    {{
      "event": "provider.identity.exists",
      "severity": "warning",
      "trust_relevant": false
    }}
  ],
  "warnings": [
    "existing identity state was not overwritten",
    "private material was not printed"
  ],
  "private_material_included": false,
  "data": {{
    "device_label": "{device_label}",
    "identity_created": false,
    "state_written": false,
    "state_path_hint": "{state_path_hint}"
  }}
}}"#,
        provider = PROVIDER_NAME,
        implementation = IMPLEMENTATION,
        mode = MODE,
        phase = PHASE_IDENTITY_CREATE,
        device_label = json_escape(device_label),
        state_path_hint = json_escape(&state_dir_hint),
    );
}

fn print_identity_create_state_write_failed(device_label: &str, reason: &str) {
    println!(
        r#"{{
  "ok": false,
  "command": "identity-create",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "state_write_failed",
    "message": "identity prep state write failed: {reason}",
    "provider_event": "checkpoint.failed",
    "severity": "warning",
    "trust_relevant": false
  }},
  "events": [
    {{
      "event": "checkpoint.failed",
      "severity": "warning",
      "trust_relevant": false
    }}
  ],
  "warnings": [],
  "private_material_included": false,
  "data": {{
    "device_label": "{device_label}",
    "identity_created": false,
    "state_written": false
  }}
}}"#,
        provider = PROVIDER_NAME,
        implementation = IMPLEMENTATION,
        mode = MODE,
        phase = PHASE_IDENTITY_CREATE,
        reason = json_escape(reason),
        device_label = json_escape(device_label),
    );
}
fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_info_constants_are_phase2d_bootstrap() {
        assert_eq!(PROVIDER_NAME, "openmls");
        assert_eq!(IMPLEMENTATION, "carbonstack-openmls-sidecar");
        assert_eq!(MODE, "experimental-sidecar");
        assert_eq!(PHASE_PROVIDER_INFO, "phase2d-provider-info");
        assert_eq!(PHASE_IDENTITY_CREATE, "phase2d-identity-create-dev");
    }

    #[test]
    fn unsupported_commands_exclude_identity_create_after_recognition() {
        assert!(!UNSUPPORTED_COMMANDS.contains(&"identity-create"));
        assert!(UNSUPPORTED_COMMANDS.contains(&"message-protect"));
        assert!(UNSUPPORTED_COMMANDS.contains(&"message-open"));
        assert!(UNSUPPORTED_COMMANDS.contains(&"state-checkpoint"));
    }

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
}
