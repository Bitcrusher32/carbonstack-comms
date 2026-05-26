use serde_json::json;

const PROVIDER_NAME: &str = "openmls";
const IMPLEMENTATION: &str = "carbonstack-openmls-sidecar";
const MODE: &str = "experimental-sidecar";

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
