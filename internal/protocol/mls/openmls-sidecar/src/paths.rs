use std::path::{Path, PathBuf};

pub const STATE_ROOT: &str = ".carbonstack-openmls-sidecar-state";
pub const DEV_SCOPE: &str = "dev";

pub fn device_state_dir(device_label: &str) -> PathBuf {
    Path::new(STATE_ROOT)
        .join(DEV_SCOPE)
        .join("devices")
        .join(device_label)
}

pub fn identity_prep_manifest_path(device_label: &str) -> PathBuf {
    device_state_dir(device_label).join("identity-prep.json")
}

pub fn identity_summary_path(device_label: &str) -> PathBuf {
    device_state_dir(device_label).join("identity-summary.json")
}

pub fn identity_state_path(device_label: &str) -> PathBuf {
    device_state_dir(device_label).join("identity-state.json")
}

pub fn signer_path(device_label: &str) -> PathBuf {
    device_state_dir(device_label).join("signer.json")
}

pub fn public_bundle_summary_path(device_label: &str) -> PathBuf {
    device_state_dir(device_label).join("public-bundle-summary.json")
}

pub fn public_bundle_keypackage_artifact_path(device_label: &str) -> PathBuf {
    device_state_dir(device_label).join("public-bundle.keypackage.bin")
}

pub fn public_bundle_manifest_path(device_label: &str) -> PathBuf {
    device_state_dir(device_label).join("public-bundle-manifest.json")
}

pub fn device_provider_storage_path(device_label: &str) -> PathBuf {
    device_state_dir(device_label).join("provider-storage.json")
}

pub fn device_conversations_dir(device_label: &str) -> PathBuf {
    device_state_dir(device_label).join("conversations")
}

pub fn device_conversation_state_dir(device_label: &str, conversation_label: &str) -> PathBuf {
    device_conversations_dir(device_label).join(conversation_label)
}

pub fn device_conversation_summary_path(device_label: &str, conversation_label: &str) -> PathBuf {
    device_conversation_state_dir(device_label, conversation_label)
        .join("conversation-summary.json")
}

pub fn device_conversation_provider_storage_path(
    device_label: &str,
    conversation_label: &str,
) -> PathBuf {
    device_conversation_state_dir(device_label, conversation_label).join("provider-storage.json")
}

pub fn device_conversation_join_summary_path(
    device_label: &str,
    conversation_label: &str,
) -> PathBuf {
    device_conversation_state_dir(device_label, conversation_label).join("join-summary.json")
}

pub fn device_conversation_welcome_artifact_path(
    device_label: &str,
    conversation_label: &str,
) -> PathBuf {
    device_conversation_state_dir(device_label, conversation_label).join("welcome.bin")
}

pub fn device_conversation_welcome_manifest_path(
    device_label: &str,
    conversation_label: &str,
) -> PathBuf {
    device_conversation_state_dir(device_label, conversation_label).join("welcome-manifest.json")
}

pub fn device_conversation_add_member_summary_path(
    device_label: &str,
    conversation_label: &str,
) -> PathBuf {
    device_conversation_state_dir(device_label, conversation_label).join("add-member-summary.json")
}

pub fn device_conversation_messages_dir(device_label: &str, conversation_label: &str) -> PathBuf {
    device_conversation_state_dir(device_label, conversation_label).join("messages")
}

pub fn device_conversation_message_dir(
    device_label: &str,
    conversation_label: &str,
    message_label: &str,
) -> PathBuf {
    device_conversation_messages_dir(device_label, conversation_label).join(message_label)
}

pub fn device_conversation_message_artifact_path(
    device_label: &str,
    conversation_label: &str,
    message_label: &str,
) -> PathBuf {
    device_conversation_message_dir(device_label, conversation_label, message_label)
        .join("application-message.bin")
}

pub fn device_conversation_message_manifest_path(
    device_label: &str,
    conversation_label: &str,
    message_label: &str,
) -> PathBuf {
    device_conversation_message_dir(device_label, conversation_label, message_label)
        .join("message-manifest.json")
}

pub fn device_conversation_message_protect_summary_path(
    device_label: &str,
    conversation_label: &str,
    message_label: &str,
) -> PathBuf {
    device_conversation_message_dir(device_label, conversation_label, message_label)
        .join("message-protect-summary.json")
}

pub fn device_conversation_message_open_summary_path(
    device_label: &str,
    conversation_label: &str,
    message_label: &str,
) -> PathBuf {
    device_conversation_state_dir(device_label, conversation_label)
        .join("opened-messages")
        .join(message_label)
        .join("message-open-summary.json")
}
