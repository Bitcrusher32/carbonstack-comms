mod labels;
mod provider;
mod state;

use labels::{validate_conversation_label, validate_device_label};
use state::{
    ConversationAddMemberResult, ConversationCreateResult, ConversationLoadCheckResult,
    IdentityCreateResult, IdentityStatusResult, PublicBundleExportResult,
    add_dev_conversation_member, create_dev_conversation, create_dev_identity, device_state_dir,
    export_dev_public_bundle_summary, load_dev_conversation_status, load_dev_identity_status,
};
use std::env;
use std::io;

const PROVIDER_NAME: &str = "openmls";
const IMPLEMENTATION: &str = "carbonstack-openmls-sidecar";
const MODE: &str = "experimental-sidecar";
const PHASE_PROVIDER_INFO: &str = "phase2d-provider-info";
const PHASE_IDENTITY_CREATE: &str = "phase2d-identity-create-dev";
const PHASE_IDENTITY_STATUS: &str = "phase2d-identity-status-dev";
const PHASE_PUBLIC_BUNDLE_EXPORT: &str = "phase2d-public-bundle-export-dev";
const PHASE_CONVERSATION_CREATE: &str = "phase2d-conversation-create-dev";
const PHASE_CONVERSATION_ADD_MEMBER: &str = "phase2d-conversation-add-member-dev";

const WARNINGS: [&str; 4] = [
    "OpenMLS is not wired into CarbonStackComms",
    "Cypher does not route MLS payloads",
    "trust-state storage does not consume provider events",
    "identity-create writes dev-only secret-bearing signer state but never prints private material",
];

const UNSUPPORTED_COMMANDS: &[&str] = &[
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
        Some("identity-status") => handle_identity_status(&args[2..]),
        Some("public-bundle-export") => handle_public_bundle_export(&args[2..]),
        Some("conversation-create") => handle_conversation_create(&args[2..]),
        Some("conversation-load-check") => handle_conversation_load_check(&args[2..]),
        Some("conversation-add-member") => handle_conversation_add_member(&args[2..]),
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

fn handle_identity_status(args: &[String]) {
    let Some(device_label) = parse_device_label(args) else {
        print_identity_status_missing_label();
        std::process::exit(2);
    };

    if let Err(reason) = validate_device_label(device_label) {
        print_identity_status_invalid_label(device_label, &reason);
        std::process::exit(2);
    }

    match load_dev_identity_status(device_label) {
        Ok(result) => {
            print_identity_status_success(&result);
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            print_identity_status_missing(device_label);
            std::process::exit(3);
        }
        Err(err) if err.kind() == io::ErrorKind::InvalidData => {
            print_identity_status_unloadable(device_label, &err.to_string());
            std::process::exit(4);
        }
        Err(err) => {
            print_identity_status_unloadable(device_label, &err.to_string());
            std::process::exit(4);
        }
    }
}

fn handle_public_bundle_export(args: &[String]) {
    let Some(device_label) = parse_device_label(args) else {
        print_public_bundle_export_missing_label();
        std::process::exit(2);
    };

    if let Err(reason) = validate_device_label(device_label) {
        print_public_bundle_export_invalid_label(device_label, &reason);
        std::process::exit(2);
    }

    let write_artifact = args.iter().any(|arg| arg == "--write-artifact");

    match export_dev_public_bundle_summary(device_label, write_artifact) {
        Ok(result) => {
            print_public_bundle_export_success(&result);
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            print_public_bundle_export_identity_missing(device_label);
            std::process::exit(3);
        }
        Err(err) if err.kind() == io::ErrorKind::InvalidData => {
            print_public_bundle_export_unloadable_identity(device_label, &err.to_string());
            std::process::exit(4);
        }
        Err(err) => {
            print_public_bundle_export_failed(device_label, &err.to_string());
            std::process::exit(4);
        }
    }
}

fn parse_conversation_label(args: &[String]) -> Option<&str> {
    let mut index = 0;

    while index < args.len() {
        if args[index] == "--conversation-label" {
            return args.get(index + 1).map(String::as_str);
        }

        index += 1;
    }

    None
}

fn handle_conversation_create(args: &[String]) {
    let Some(device_label) = parse_device_label(args) else {
        print_conversation_create_missing_device_label();
        std::process::exit(2);
    };

    let Some(conversation_label) = parse_conversation_label(args) else {
        print_conversation_create_missing_conversation_label(device_label);
        std::process::exit(2);
    };

    if let Err(reason) = validate_device_label(device_label) {
        print_conversation_create_invalid_device_label(device_label, &reason);
        std::process::exit(2);
    }

    if let Err(reason) = validate_conversation_label(conversation_label) {
        print_conversation_create_invalid_conversation_label(
            device_label,
            conversation_label,
            &reason,
        );
        std::process::exit(2);
    }

    match create_dev_conversation(device_label, conversation_label) {
        Ok(result) => {
            print_conversation_create_success(&result);
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            print_conversation_create_identity_missing(device_label, conversation_label);
            std::process::exit(3);
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            print_conversation_create_already_exists(device_label, conversation_label);
            std::process::exit(3);
        }
        Err(err) if err.kind() == io::ErrorKind::InvalidData => {
            print_conversation_create_secret_material_unavailable(
                device_label,
                conversation_label,
                &err.to_string(),
            );
            std::process::exit(4);
        }
        Err(err) => {
            print_conversation_create_failed(device_label, conversation_label, &err.to_string());
            std::process::exit(4);
        }
    }
}

fn print_conversation_create_success(result: &ConversationCreateResult) {
    let envelope = serde_json::json!({
        "ok": true,
        "command": "conversation-create",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": PHASE_CONVERSATION_CREATE,
        "data": {
            "device_label": result.device_label,
            "conversation_label": result.conversation_label,
            "identity_exists": true,
            "identity_loadable": true,
            "conversation_created": true,
            "state_scope": "dev-local-sidecar-state",
            "conversation_state_path_hint": result.conversation_state_dir.to_string_lossy(),
            "conversation_summary_path_hint": result.conversation_summary_path.to_string_lossy(),
            "provider_storage_path_hint": result.provider_storage_path.to_string_lossy(),
            "ciphersuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_id_ref": result.group_id_ref,
            "group_id_len": result.group_id_len,
            "member_count": result.member_count,
            "epoch": result.epoch,
            "provider_storage_written": result.provider_storage_written,
            "group_reloadable": result.group_reloadable,
        },
        "events": [
            {
                "event": "provider.conversation.created",
                "severity": "info",
                "trust_relevant": false
            }
        ],
        "warnings": [
            "dev-only OpenMLS conversation state; not production messaging",
            "conversation group is reloadable through dev-local provider storage",
            "provider storage is dev-only and not production secure vault storage",
            "private material was loaded locally but not printed",
            "conversation-add-member is implemented for dev-local Welcome export",
            "conversation-join is not implemented",
            "message protect/open is not implemented"
        ],
        "private_material_included": false
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope)
            .expect("failed to serialize conversation-create success envelope")
    );
}

fn print_conversation_create_missing_device_label() {
    println!(
        r#"{{
  "ok": false,
  "command": "conversation-create",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "missing_required_argument",
    "message": "conversation-create requires --device-label <label>",
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
        phase = PHASE_CONVERSATION_CREATE,
    );
}

fn print_conversation_create_missing_conversation_label(device_label: &str) {
    println!(
        r#"{{
  "ok": false,
  "command": "conversation-create",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "missing_required_argument",
    "message": "conversation-create requires --conversation-label <label>",
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
        phase = PHASE_CONVERSATION_CREATE,
        device_label = json_escape(device_label),
    );
}

fn print_conversation_create_invalid_device_label(device_label: &str, reason: &str) {
    print_conversation_create_invalid_label_common(
        device_label,
        "",
        "invalid_device_label",
        &format!("invalid device label: {reason}"),
    );
}

fn print_conversation_create_invalid_conversation_label(
    device_label: &str,
    conversation_label: &str,
    reason: &str,
) {
    print_conversation_create_invalid_label_common(
        device_label,
        conversation_label,
        "invalid_conversation_label",
        &format!("invalid conversation label: {reason}"),
    );
}

fn print_conversation_create_invalid_label_common(
    device_label: &str,
    conversation_label: &str,
    code: &str,
    message: &str,
) {
    let envelope = serde_json::json!({
        "ok": false,
        "command": "conversation-create",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": PHASE_CONVERSATION_CREATE,
        "error": {
            "code": code,
            "message": message,
            "provider_event": "provider.command.invalid",
            "severity": "warning",
            "trust_relevant": false
        },
        "events": [
            {
                "event": "provider.command.invalid",
                "severity": "warning",
                "trust_relevant": false
            }
        ],
        "warnings": [],
        "private_material_included": false,
        "data": {
            "device_label": device_label,
            "conversation_label": conversation_label
        }
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope)
            .expect("failed to serialize conversation-create invalid label envelope")
    );
}

fn parse_member_keypackage_path(args: &[String]) -> Option<&str> {
    let mut index = 0;

    while index < args.len() {
        if args[index] == "--member-keypackage" {
            return args.get(index + 1).map(String::as_str);
        }

        index += 1;
    }

    None
}

fn handle_conversation_add_member(args: &[String]) {
    let Some(device_label) = parse_device_label(args) else {
        print_conversation_add_member_missing_argument("--device-label");
        std::process::exit(2);
    };

    let Some(conversation_label) = parse_conversation_label(args) else {
        print_conversation_add_member_missing_argument("--conversation-label");
        std::process::exit(2);
    };

    let Some(member_keypackage_path) = parse_member_keypackage_path(args) else {
        print_conversation_add_member_missing_argument("--member-keypackage");
        std::process::exit(2);
    };

    if let Err(reason) = validate_device_label(device_label) {
        print_conversation_add_member_invalid_label(
            device_label,
            conversation_label,
            member_keypackage_path,
            "invalid_device_label",
            &reason,
        );
        std::process::exit(2);
    }

    if let Err(reason) = validate_conversation_label(conversation_label) {
        print_conversation_add_member_invalid_label(
            device_label,
            conversation_label,
            member_keypackage_path,
            "invalid_conversation_label",
            &reason,
        );
        std::process::exit(2);
    }

    match add_dev_conversation_member(
        device_label,
        conversation_label,
        std::path::Path::new(member_keypackage_path),
    ) {
        Ok(result) => {
            print_conversation_add_member_success(&result);
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            print_conversation_add_member_failed(
                device_label,
                conversation_label,
                member_keypackage_path,
                "conversation_or_artifact_missing",
                &err,
                "provider.conversation.missing",
                "warning",
                false,
            );
            std::process::exit(3);
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            print_conversation_add_member_failed(
                device_label,
                conversation_label,
                member_keypackage_path,
                "add_member_artifact_exists",
                &err,
                "provider.conversation.exists",
                "warning",
                false,
            );
            std::process::exit(3);
        }
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => {
            print_conversation_add_member_failed(
                device_label,
                conversation_label,
                member_keypackage_path,
                "invalid_member_keypackage_path",
                &err,
                "provider.command.invalid",
                "warning",
                false,
            );
            std::process::exit(2);
        }
        Err(err) if err.kind() == io::ErrorKind::InvalidData => {
            print_conversation_add_member_failed(
                device_label,
                conversation_label,
                member_keypackage_path,
                "member_keypackage_invalid",
                &err,
                "provider.artifact.invalid",
                "warning",
                false,
            );
            std::process::exit(3);
        }
        Err(err) => {
            print_conversation_add_member_failed(
                device_label,
                conversation_label,
                member_keypackage_path,
                "conversation_add_member_failed",
                &err,
                "checkpoint.failed",
                "warning",
                false,
            );
            std::process::exit(3);
        }
    }
}

fn print_conversation_add_member_success(result: &ConversationAddMemberResult) {
    let envelope = serde_json::json!({
        "ok": true,
        "command": "conversation-add-member",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": PHASE_CONVERSATION_ADD_MEMBER,
        "private_material_included": false,
        "data": {
            "device_label": result.device_label,
            "conversation_label": result.conversation_label,
            "conversation_state_path_hint": result.conversation_state_dir.to_string_lossy(),
            "conversation_summary_path_hint": result.conversation_summary_path.to_string_lossy(),
            "provider_storage_path_hint": result.provider_storage_path.to_string_lossy(),
            "member_keypackage_path_hint": result.member_keypackage_path.to_string_lossy(),
            "welcome_artifact_path_hint": result.welcome_artifact_path.to_string_lossy(),
            "welcome_manifest_path_hint": result.welcome_manifest_path.to_string_lossy(),
            "add_member_summary_path_hint": result.add_member_summary_path.to_string_lossy(),
            "group_id_ref": result.group_id_ref,
            "group_id_len": result.group_id_len,
            "provider_storage_loaded": result.provider_storage_loaded,
            "provider_storage_written": result.provider_storage_written,
            "group_reloadable": result.group_reloadable,
            "member_added": result.member_added,
            "welcome_artifact_written": result.welcome_artifact_written,
            "pending_commit_merged": result.pending_commit_merged,
            "member_count_before": result.member_count_before,
            "member_count_after": result.member_count_after,
            "epoch_before": result.epoch_before,
            "epoch_after": result.epoch_after,
            "welcome_artifact_sha256": result.welcome_artifact_sha256,
            "welcome_artifact_size_bytes": result.welcome_artifact_size_bytes,
            "state_scope": "dev-local-sidecar-state"
        },
        "events": [
            {
                "event": "provider.conversation.member_added",
                "severity": "info",
                "trust_relevant": false
            },
            {
                "event": "provider.welcome.exported",
                "severity": "info",
                "trust_relevant": false
            }
        ],
        "warnings": [
            "dev-only OpenMLS add-member and Welcome export",
            "Welcome artifact was written but not printed",
            "provider storage is dev-only and not production secure vault storage",
            "conversation-join is not implemented",
            "message protect/open is not implemented"
        ]
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope).expect("provider envelope JSON should serialize")
    );
}

fn print_conversation_add_member_missing_argument(argument: &str) {
    let envelope = serde_json::json!({
        "ok": false,
        "command": "conversation-add-member",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": PHASE_CONVERSATION_ADD_MEMBER,
        "private_material_included": false,
        "error": {
            "code": "missing_required_argument",
            "message": format!("conversation-add-member requires {argument}")
        },
        "events": [
            {
                "event": "provider.command.invalid",
                "severity": "warning",
                "trust_relevant": false
            }
        ],
        "warnings": [
            "missing required conversation-add-member argument",
            "no private material printed"
        ]
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope).expect("provider envelope JSON should serialize")
    );
}

fn print_conversation_add_member_invalid_label(
    device_label: &str,
    conversation_label: &str,
    member_keypackage_path: &str,
    code: &str,
    reason: &str,
) {
    let envelope = serde_json::json!({
        "ok": false,
        "command": "conversation-add-member",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": PHASE_CONVERSATION_ADD_MEMBER,
        "private_material_included": false,
        "error": {
            "code": code,
            "message": reason
        },
        "data": {
            "device_label": device_label,
            "conversation_label": conversation_label,
            "member_keypackage_path_hint": member_keypackage_path,
            "member_added": false,
            "welcome_artifact_written": false,
            "provider_storage_written": false
        },
        "events": [
            {
                "event": "provider.command.invalid",
                "severity": "warning",
                "trust_relevant": false
            }
        ],
        "warnings": [
            "invalid conversation-add-member label",
            "no private material printed"
        ]
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope).expect("provider envelope JSON should serialize")
    );
}

fn print_conversation_add_member_failed(
    device_label: &str,
    conversation_label: &str,
    member_keypackage_path: &str,
    code: &str,
    err: &io::Error,
    provider_event: &str,
    severity: &str,
    trust_relevant: bool,
) {
    let envelope = serde_json::json!({
        "ok": false,
        "command": "conversation-add-member",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": PHASE_CONVERSATION_ADD_MEMBER,
        "private_material_included": false,
        "error": {
            "code": code,
            "message": err.to_string(),
            "provider_event": provider_event,
            "severity": severity,
            "trust_relevant": trust_relevant
        },
        "data": {
            "device_label": device_label,
            "conversation_label": conversation_label,
            "member_keypackage_path_hint": member_keypackage_path,
            "member_added": false,
            "welcome_artifact_written": false,
            "provider_storage_written": false
        },
        "events": [
            {
                "event": provider_event,
                "severity": severity,
                "trust_relevant": trust_relevant
            }
        ],
        "warnings": [
            "conversation-add-member failed",
            "no private material printed"
        ]
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope).expect("provider envelope JSON should serialize")
    );
}
fn handle_conversation_load_check(args: &[String]) {
    let Some(device_label) = parse_device_label(args) else {
        print_conversation_load_check_missing_argument("--device-label");
        std::process::exit(2);
    };

    let Some(conversation_label) = parse_conversation_label(args) else {
        print_conversation_load_check_missing_argument("--conversation-label");
        std::process::exit(2);
    };

    if let Err(reason) = validate_device_label(device_label) {
        print_conversation_load_check_invalid_label(
            device_label,
            conversation_label,
            "invalid_device_label",
            &reason,
        );
        std::process::exit(2);
    }

    if let Err(reason) = validate_conversation_label(conversation_label) {
        print_conversation_load_check_invalid_label(
            device_label,
            conversation_label,
            "invalid_conversation_label",
            &reason,
        );
        std::process::exit(2);
    }

    match load_dev_conversation_status(device_label, conversation_label) {
        Ok(result) => {
            print_conversation_load_check_success(&result);
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            print_conversation_load_check_missing(device_label, conversation_label, &err);
            std::process::exit(3);
        }
        Err(err) => {
            print_conversation_load_check_unavailable(device_label, conversation_label, &err);
            std::process::exit(3);
        }
    }
}

fn print_conversation_load_check_success(result: &ConversationLoadCheckResult) {
    let envelope = serde_json::json!({
        "ok": true,
        "command": "conversation-load-check",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": "phase2d-conversation-load-check-dev",
        "private_material_included": false,
        "data": {
            "device_label": result.device_label,
            "conversation_label": result.conversation_label,
            "conversation_state_path_hint": result.conversation_state_dir.to_string_lossy(),
            "conversation_summary_path_hint": result.conversation_summary_path.to_string_lossy(),
            "provider_storage_path_hint": result.provider_storage_path.to_string_lossy(),
            "provider_storage_loaded": result.provider_storage_loaded,
            "group_reloadable": result.group_reloadable,
            "group_id_ref": result.group_id_ref,
            "group_id_len": result.group_id_len,
            "member_count": result.member_count,
            "epoch": result.epoch,
            "state_scope": "dev-local-sidecar-state"
        },
        "events": [
            {
                "event": "conversation.loaded",
                "severity": "info",
                "trust_relevant": false
            }
        ],
        "warnings": [
            "dev-only OpenMLS conversation provider storage loaded",
            "provider storage is not production secure vault storage",
            "private material may be required locally by OpenMLS but is not printed",
            "conversation-add-member is implemented for dev-local Welcome export",
            "conversation-join is not implemented",
            "message protect/open is not implemented"
        ]
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope).expect("provider envelope JSON should serialize")
    );
}

fn print_conversation_load_check_missing_argument(argument: &str) {
    let envelope = serde_json::json!({
        "ok": false,
        "command": "conversation-load-check",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": "phase2d-conversation-load-check-dev",
        "private_material_included": false,
        "error": {
            "code": "missing_required_argument",
            "message": format!("conversation-load-check requires {argument}")
        },
        "events": [
            {
                "event": "provider.command.invalid",
                "severity": "warning",
                "trust_relevant": false
            }
        ],
        "warnings": [
            "missing required conversation-load-check argument",
            "no private material printed"
        ]
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope).expect("provider envelope JSON should serialize")
    );
}

fn print_conversation_load_check_invalid_label(
    device_label: &str,
    conversation_label: &str,
    code: &str,
    reason: &str,
) {
    let envelope = serde_json::json!({
        "ok": false,
        "command": "conversation-load-check",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": "phase2d-conversation-load-check-dev",
        "private_material_included": false,
        "error": {
            "code": code,
            "message": reason
        },
        "data": {
            "device_label": device_label,
            "conversation_label": conversation_label,
            "provider_storage_loaded": false,
            "group_reloadable": false
        },
        "events": [
            {
                "event": "provider.command.invalid",
                "severity": "warning",
                "trust_relevant": false
            }
        ],
        "warnings": [
            "invalid conversation-load-check label",
            "no private material printed"
        ]
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope).expect("provider envelope JSON should serialize")
    );
}

fn print_conversation_load_check_missing(
    device_label: &str,
    conversation_label: &str,
    err: &io::Error,
) {
    let envelope = serde_json::json!({
        "ok": false,
        "command": "conversation-load-check",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": "phase2d-conversation-load-check-dev",
        "private_material_included": false,
        "error": {
            "code": "conversation_missing",
            "message": err.to_string()
        },
        "data": {
            "device_label": device_label,
            "conversation_label": conversation_label,
            "provider_storage_loaded": false,
            "group_reloadable": false
        },
        "events": [
            {
                "event": "provider.conversation.missing",
                "severity": "warning",
                "trust_relevant": false
            }
        ],
        "warnings": [
            "conversation summary or provider storage is missing",
            "no private material printed"
        ]
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope).expect("provider envelope JSON should serialize")
    );
}

fn print_conversation_load_check_unavailable(
    device_label: &str,
    conversation_label: &str,
    err: &io::Error,
) {
    let envelope = serde_json::json!({
        "ok": false,
        "command": "conversation-load-check",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": "phase2d-conversation-load-check-dev",
        "private_material_included": false,
        "error": {
            "code": "provider_storage_unavailable",
            "message": err.to_string()
        },
        "data": {
            "device_label": device_label,
            "conversation_label": conversation_label,
            "provider_storage_loaded": false,
            "group_reloadable": false
        },
        "events": [
            {
                "event": "storage.corrupt",
                "severity": "warning",
                "trust_relevant": false
            }
        ],
        "warnings": [
            "provider storage could not be loaded or did not contain a reloadable group",
            "no private material printed"
        ]
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope).expect("provider envelope JSON should serialize")
    );
}
fn print_conversation_create_identity_missing(device_label: &str, conversation_label: &str) {
    print_conversation_create_failure_common(
        device_label,
        conversation_label,
        "identity_missing",
        "identity state is missing",
        "provider.identity.missing",
        "warning",
        false,
    );
}

fn print_conversation_create_already_exists(device_label: &str, conversation_label: &str) {
    print_conversation_create_failure_common(
        device_label,
        conversation_label,
        "conversation_already_exists",
        "conversation state already exists; refusing overwrite",
        "provider.conversation.exists",
        "warning",
        false,
    );
}

fn print_conversation_create_secret_material_unavailable(
    device_label: &str,
    conversation_label: &str,
    reason: &str,
) {
    print_conversation_create_failure_common(
        device_label,
        conversation_label,
        "secret_material_unavailable",
        &format!("identity secret material is unavailable or unloadable: {reason}"),
        "provider.secret.material.unavailable",
        "fatal",
        true,
    );
}

fn print_conversation_create_failed(device_label: &str, conversation_label: &str, reason: &str) {
    print_conversation_create_failure_common(
        device_label,
        conversation_label,
        "conversation_create_failed",
        &format!("conversation create failed: {reason}"),
        "checkpoint.failed",
        "warning",
        false,
    );
}

fn print_conversation_create_failure_common(
    device_label: &str,
    conversation_label: &str,
    code: &str,
    message: &str,
    provider_event: &str,
    severity: &str,
    trust_relevant: bool,
) {
    let envelope = serde_json::json!({
        "ok": false,
        "command": "conversation-create",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": PHASE_CONVERSATION_CREATE,
        "error": {
            "code": code,
            "message": message,
            "provider_event": provider_event,
            "severity": severity,
            "trust_relevant": trust_relevant
        },
        "events": [
            {
                "event": provider_event,
                "severity": severity,
                "trust_relevant": trust_relevant
            }
        ],
        "warnings": [],
        "private_material_included": false,
        "data": {
            "device_label": device_label,
            "conversation_label": conversation_label
        }
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope)
            .expect("failed to serialize conversation-create failure envelope")
    );
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
      "identity-create",
    "identity-status",
    "public-bundle-export",
    "conversation-create",
    "conversation-load-check",
    "conversation-add-member"
    ],
    "unsupported": [

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

fn print_public_bundle_export_missing_label() {
    println!(
        r#"{{
  "ok": false,
  "command": "public-bundle-export",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "missing_required_argument",
    "message": "public-bundle-export requires --device-label <label>",
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
        phase = PHASE_PUBLIC_BUNDLE_EXPORT,
    );
}

fn print_public_bundle_export_invalid_label(device_label: &str, reason: &str) {
    println!(
        r#"{{
  "ok": false,
  "command": "public-bundle-export",
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
        phase = PHASE_PUBLIC_BUNDLE_EXPORT,
        reason = json_escape(reason),
        device_label = json_escape(device_label),
    );
}

fn print_public_bundle_export_success(result: &PublicBundleExportResult) {
    let envelope = serde_json::json!({
        "ok": true,
        "command": "public-bundle-export",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": PHASE_PUBLIC_BUNDLE_EXPORT,
        "data": {
            "device_label": result.device_label,
            "identity_exists": true,
            "identity_loadable": true,
            "public_bundle_exported": true,
            "public_bundle_available": true,
            "key_package_created": true,
            "key_package_artifact_written": result.key_package_artifact_written,
            "key_package_artifact_path_hint": result.key_package_artifact_path,
            "key_package_artifact_sha256": result.key_package_artifact_sha256,
            "key_package_artifact_size_bytes": result.key_package_artifact_size_bytes,
            "public_bundle_manifest_written": result.public_bundle_manifest_written,
            "public_bundle_manifest_path_hint": result.public_bundle_manifest_path,
            "state_scope": "dev-local-sidecar-state",
            "state_path_hint": result.state_dir.to_string_lossy(),
            "public_bundle_summary_path_hint": result.public_bundle_summary_path.to_string_lossy(),
            "public_identity_ref": result.public_identity_ref,
            "public_signature_key_len": result.public_signature_key_len,
            "key_package_ref": result.key_package_ref,
            "key_package_hash_len": result.key_package_hash_len,
            "provider_storage_written": result.provider_storage_written,
        },
        "events": [
            {
                "event": "provider.public_bundle.exported",
                "severity": "info",
                "trust_relevant": false
            }
        ],
        "warnings": [
            "dev-only public bundle summary; not production onboarding material",
            if result.key_package_artifact_written {
                "serialized public KeyPackage artifact was written under ignored dev state"
            } else {
                "full serialized KeyPackage artifact is not exported in this rung"
            },
            "private material was loaded locally but not printed",
            "OpenMLS is not wired into CarbonStackComms",
            "conversation lifecycle is not implemented"
        ],
        "private_material_included": false
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope)
            .expect("failed to serialize public-bundle-export success envelope")
    );
}

fn print_public_bundle_export_identity_missing(device_label: &str) {
    let state_dir = device_state_dir(device_label);
    let state_dir_hint = state_dir.to_string_lossy();

    println!(
        r#"{{
  "ok": false,
  "command": "public-bundle-export",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "identity_missing",
    "message": "identity state is missing",
    "provider_event": "provider.identity.missing",
    "severity": "warning",
    "trust_relevant": false
  }},
  "events": [
    {{
      "event": "provider.identity.missing",
      "severity": "warning",
      "trust_relevant": false
    }}
  ],
  "warnings": [],
  "private_material_included": false,
  "data": {{
    "device_label": "{device_label}",
    "identity_exists": false,
    "identity_loadable": false,
    "state_path_hint": "{state_path_hint}"
  }}
}}"#,
        provider = PROVIDER_NAME,
        implementation = IMPLEMENTATION,
        mode = MODE,
        phase = PHASE_PUBLIC_BUNDLE_EXPORT,
        device_label = json_escape(device_label),
        state_path_hint = json_escape(&state_dir_hint),
    );
}

fn print_public_bundle_export_unloadable_identity(device_label: &str, reason: &str) {
    println!(
        r#"{{
  "ok": false,
  "command": "public-bundle-export",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "secret_material_unavailable",
    "message": "identity secret material is unavailable or unloadable: {reason}",
    "provider_event": "provider.secret.material.unavailable",
    "severity": "fatal",
    "trust_relevant": true
  }},
  "events": [
    {{
      "event": "provider.secret.material.unavailable",
      "severity": "fatal",
      "trust_relevant": true
    }}
  ],
  "warnings": [
    "identity state could not be loaded",
    "private material was not printed"
  ],
  "private_material_included": false,
  "data": {{
    "device_label": "{device_label}",
    "identity_exists": true,
    "identity_loadable": false
  }}
}}"#,
        provider = PROVIDER_NAME,
        implementation = IMPLEMENTATION,
        mode = MODE,
        phase = PHASE_PUBLIC_BUNDLE_EXPORT,
        reason = json_escape(reason),
        device_label = json_escape(device_label),
    );
}

fn print_public_bundle_export_failed(device_label: &str, reason: &str) {
    println!(
        r#"{{
  "ok": false,
  "command": "public-bundle-export",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "public_bundle_export_failed",
    "message": "public bundle export failed: {reason}",
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
  "warnings": [
    "public bundle summary was not exported"
  ],
  "private_material_included": false,
  "data": {{
    "device_label": "{device_label}"
  }}
}}"#,
        provider = PROVIDER_NAME,
        implementation = IMPLEMENTATION,
        mode = MODE,
        phase = PHASE_PUBLIC_BUNDLE_EXPORT,
        reason = json_escape(reason),
        device_label = json_escape(device_label),
    );
}
fn print_identity_status_missing_label() {
    println!(
        r#"{{
  "ok": false,
  "command": "identity-status",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "missing_required_argument",
    "message": "identity-status requires --device-label <label>",
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
        phase = PHASE_IDENTITY_STATUS,
    );
}

fn print_identity_status_invalid_label(device_label: &str, reason: &str) {
    println!(
        r#"{{
  "ok": false,
  "command": "identity-status",
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
        phase = PHASE_IDENTITY_STATUS,
        reason = json_escape(reason),
        device_label = json_escape(device_label),
    );
}

fn print_identity_status_success(result: &IdentityStatusResult) {
    let envelope = serde_json::json!({
        "ok": true,
        "command": "identity-status",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": PHASE_IDENTITY_STATUS,
        "data": {
            "device_label": result.device_label,
            "identity_exists": true,
            "identity_loadable": true,
            "identity_created": result.identity_created,
            "state_scope": "dev-local-sidecar-state",
            "state_path_hint": result.state_dir.to_string_lossy(),
            "identity_summary_path_hint": result.identity_summary_path.to_string_lossy(),
            "identity_state_path_hint": result.identity_state_path.to_string_lossy(),
            "signer_path_hint": result.signer_path.to_string_lossy(),
            "public_identity_ref": result.public_identity_ref,
            "public_signature_key_len": result.public_signature_key_len,
            "provider_storage_written": result.provider_storage_written,
            "public_bundle_available": result.public_bundle_available
        },
        "events": [
            {
                "event": "provider.identity.loaded",
                "severity": "info",
                "trust_relevant": false
            }
        ],
        "warnings": [
            "dev-only identity status; not production secure storage",
            "private material was loaded locally but not printed",
            "OpenMLS is not wired into CarbonStackComms",
            "public bundle export is not implemented"
        ],
        "private_material_included": false
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope)
            .expect("failed to serialize identity-status success envelope")
    );
}

fn print_identity_status_missing(device_label: &str) {
    let state_dir = device_state_dir(device_label);
    let state_dir_hint = state_dir.to_string_lossy();

    println!(
        r#"{{
  "ok": false,
  "command": "identity-status",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "identity_missing",
    "message": "identity state is missing",
    "provider_event": "provider.identity.missing",
    "severity": "warning",
    "trust_relevant": false
  }},
  "events": [
    {{
      "event": "provider.identity.missing",
      "severity": "warning",
      "trust_relevant": false
    }}
  ],
  "warnings": [],
  "private_material_included": false,
  "data": {{
    "device_label": "{device_label}",
    "identity_exists": false,
    "identity_loadable": false,
    "state_path_hint": "{state_path_hint}"
  }}
}}"#,
        provider = PROVIDER_NAME,
        implementation = IMPLEMENTATION,
        mode = MODE,
        phase = PHASE_IDENTITY_STATUS,
        device_label = json_escape(device_label),
        state_path_hint = json_escape(&state_dir_hint),
    );
}

fn print_identity_status_unloadable(device_label: &str, reason: &str) {
    println!(
        r#"{{
  "ok": false,
  "command": "identity-status",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "secret_material_unavailable",
    "message": "identity secret material is unavailable or unloadable: {reason}",
    "provider_event": "provider.secret.material.unavailable",
    "severity": "fatal",
    "trust_relevant": true
  }},
  "events": [
    {{
      "event": "provider.secret.material.unavailable",
      "severity": "fatal",
      "trust_relevant": true
    }}
  ],
  "warnings": [
    "identity state could not be loaded",
    "private material was not printed"
  ],
  "private_material_included": false,
  "data": {{
    "device_label": "{device_label}",
    "identity_exists": true,
    "identity_loadable": false
  }}
}}"#,
        provider = PROVIDER_NAME,
        implementation = IMPLEMENTATION,
        mode = MODE,
        phase = PHASE_IDENTITY_STATUS,
        reason = json_escape(reason),
        device_label = json_escape(device_label),
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
        assert_eq!(PHASE_IDENTITY_STATUS, "phase2d-identity-status-dev");
        assert_eq!(
            PHASE_PUBLIC_BUNDLE_EXPORT,
            "phase2d-public-bundle-export-dev"
        );
    }

    #[test]
    fn unsupported_commands_exclude_identity_create_after_recognition() {
        assert!(!UNSUPPORTED_COMMANDS.contains(&"identity-create"));
        assert!(!UNSUPPORTED_COMMANDS.contains(&"identity-status"));
        assert!(!UNSUPPORTED_COMMANDS.contains(&"public-bundle-export"));
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
