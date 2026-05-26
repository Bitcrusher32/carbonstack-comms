use crate::paths::device_state_dir;
use crate::schema::{IdentityCreateResult, IdentityStatusResult, PublicBundleExportResult};
use crate::{IMPLEMENTATION, MODE, PROVIDER_NAME};
use serde_json::json;

pub const PHASE_PROVIDER_INFO: &str = "phase2d-provider-info";
pub const PHASE_IDENTITY_CREATE: &str = "phase2d-identity-create-dev";
pub const PHASE_IDENTITY_STATUS: &str = "phase2d-identity-status-dev";
pub const PHASE_PUBLIC_BUNDLE_EXPORT: &str = "phase2d-public-bundle-export-dev";
pub const PHASE_CONVERSATION_CREATE: &str = "phase2d-conversation-create-dev";
pub const PHASE_CONVERSATION_ADD_MEMBER: &str = "phase2d-conversation-add-member-dev";
pub const PHASE_CONVERSATION_JOIN: &str = "phase2d-conversation-join-dev";
pub const PHASE_MESSAGE_PROTECT: &str = "phase2d-message-protect-dev";
pub const PHASE_MESSAGE_OPEN: &str = "phase2d-message-open-dev";

pub const WARNINGS: [&str; 4] = [
    "OpenMLS is not wired into CarbonStackComms",
    "Cypher does not route MLS payloads",
    "trust-state storage does not consume provider events",
    "dev-only signer/provider storage is not a secure vault",
];

pub const CAPABILITIES: &[&str] = &[
    "provider-info",
    "identity-create",
    "identity-status",
    "public-bundle-export",
    "conversation-create",
    "conversation-load-check",
    "conversation-add-member",
    "conversation-join",
    "message-protect",
    "message-open",
];

pub const UNSUPPORTED_COMMANDS: &[&str] = &["state-checkpoint", "state-load-check"];

pub fn print_provider_info() {
    let envelope = json!({
        "ok": true,
        "command": "provider-info",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": PHASE_PROVIDER_INFO,
        "data": {
            "capabilities": CAPABILITIES,
            "unsupported": UNSUPPORTED_COMMANDS,
            "security_level": "experimental; not production E2EE"
        },
        "events": [],
        "warnings": [
            WARNINGS[0],
            WARNINGS[1],
            WARNINGS[2],
            WARNINGS[3],
            "identity-create writes dev-only OpenMLS identity material locally but does not print private material"
        ],
        "private_material_included": false
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&envelope).expect("provider envelope JSON should serialize")
    );
}

pub fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

pub fn print_unsupported_command(command: &str) {
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

pub fn print_public_bundle_export_missing_label() {
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

pub fn print_public_bundle_export_invalid_label(device_label: &str, reason: &str) {
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

pub fn print_public_bundle_export_success(result: &PublicBundleExportResult) {
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

pub fn print_public_bundle_export_identity_missing(device_label: &str) {
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

pub fn print_public_bundle_export_unloadable_identity(device_label: &str, reason: &str) {
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

pub fn print_public_bundle_export_failed(device_label: &str, reason: &str) {
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
pub fn print_identity_status_missing_label() {
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

pub fn print_identity_status_invalid_label(device_label: &str, reason: &str) {
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

pub fn print_identity_status_success(result: &IdentityStatusResult) {
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

pub fn print_identity_status_missing(device_label: &str) {
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

pub fn print_identity_status_unloadable(device_label: &str, reason: &str) {
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
pub fn print_identity_create_missing_label() {
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

pub fn print_identity_create_invalid_label(device_label: &str, reason: &str) {
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

pub fn print_identity_create_success(result: &IdentityCreateResult) {
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
pub fn print_identity_create_already_exists(device_label: &str) {
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

pub fn print_identity_create_state_write_failed(device_label: &str, reason: &str) {
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
