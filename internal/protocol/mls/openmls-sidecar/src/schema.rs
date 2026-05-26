use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct IdentityCreateResult {
    pub device_label: String,
    pub state_dir: PathBuf,
    pub prep_manifest_path: PathBuf,
    pub identity_summary_path: PathBuf,
    pub identity_state_path: PathBuf,
    pub signer_path: PathBuf,
    pub public_identity_ref: String,
    pub public_signature_key_len: usize,
}

#[derive(Debug, Clone)]
pub struct IdentityStatusResult {
    pub device_label: String,
    pub state_dir: PathBuf,
    pub identity_summary_path: PathBuf,
    pub identity_state_path: PathBuf,
    pub signer_path: PathBuf,
    pub public_identity_ref: String,
    pub public_signature_key_len: usize,
    pub identity_created: bool,
    pub provider_storage_written: bool,
    pub public_bundle_available: bool,
}

#[derive(Debug, Clone)]
pub struct PublicBundleExportResult {
    pub device_label: String,
    pub state_dir: PathBuf,
    pub public_bundle_summary_path: PathBuf,
    pub public_identity_ref: String,
    pub public_signature_key_len: usize,
    pub key_package_ref: String,
    pub key_package_hash_len: usize,
    pub key_package_artifact_written: bool,
    pub key_package_artifact_path: Option<String>,
    pub key_package_artifact_sha256: Option<String>,
    pub key_package_artifact_size_bytes: Option<usize>,
    pub public_bundle_manifest_written: bool,
    pub public_bundle_manifest_path: Option<String>,
    pub provider_storage_written: bool,
}

#[derive(Debug, Clone)]
pub struct ConversationCreateResult {
    pub device_label: String,
    pub conversation_label: String,
    pub conversation_state_dir: PathBuf,
    pub conversation_summary_path: PathBuf,
    pub provider_storage_path: PathBuf,
    pub group_id_ref: String,
    pub group_id_len: usize,
    pub member_count: usize,
    pub epoch: String,
    pub provider_storage_written: bool,
    pub group_reloadable: bool,
}

#[derive(Debug, Clone)]
pub struct ConversationLoadCheckResult {
    pub device_label: String,
    pub conversation_label: String,
    pub conversation_state_dir: PathBuf,
    pub conversation_summary_path: PathBuf,
    pub provider_storage_path: PathBuf,
    pub group_id_ref: String,
    pub group_id_len: usize,
    pub member_count: usize,
    pub epoch: String,
    pub provider_storage_loaded: bool,
    pub group_reloadable: bool,
}

#[derive(Debug, Clone)]
pub struct ConversationAddMemberResult {
    pub device_label: String,
    pub conversation_label: String,
    pub member_keypackage_path: PathBuf,
    pub conversation_state_dir: PathBuf,
    pub conversation_summary_path: PathBuf,
    pub provider_storage_path: PathBuf,
    pub welcome_artifact_path: PathBuf,
    pub welcome_manifest_path: PathBuf,
    pub add_member_summary_path: PathBuf,
    pub group_id_ref: String,
    pub group_id_len: usize,
    pub provider_storage_loaded: bool,
    pub provider_storage_written: bool,
    pub group_reloadable: bool,
    pub member_added: bool,
    pub welcome_artifact_written: bool,
    pub pending_commit_merged: bool,
    pub member_count_before: usize,
    pub member_count_after: usize,
    pub epoch_before: String,
    pub epoch_after: String,
    pub welcome_artifact_sha256: String,
    pub welcome_artifact_size_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct ConversationJoinResult {
    pub device_label: String,
    pub conversation_label: String,
    pub welcome_artifact_path: PathBuf,
    pub conversation_state_dir: PathBuf,
    pub conversation_summary_path: PathBuf,
    pub provider_storage_path: PathBuf,
    pub join_summary_path: PathBuf,
    pub group_id_ref: String,
    pub group_id_len: usize,
    pub provider_storage_written: bool,
    pub provider_storage_loaded: bool,
    pub group_reloadable: bool,
    pub joined: bool,
    pub member_count: usize,
    pub epoch: String,
}

#[derive(Debug, Clone)]
pub struct MessageProtectResult {
    pub device_label: String,
    pub conversation_label: String,
    pub message_label: String,
    pub conversation_state_dir: PathBuf,
    pub provider_storage_path: PathBuf,
    pub message_dir: PathBuf,
    pub message_artifact_path: PathBuf,
    pub message_manifest_path: PathBuf,
    pub message_protect_summary_path: PathBuf,
    pub message_artifact_sha256: String,
    pub message_artifact_size_bytes: usize,
    pub group_id_ref: String,
    pub member_count: usize,
    pub epoch_before: String,
    pub epoch_after: String,
    pub provider_storage_loaded: bool,
    pub provider_storage_written: bool,
    pub group_reloadable: bool,
    pub message_protected: bool,
    pub protected_message_written: bool,
}

#[derive(Debug, Clone)]
pub struct MessageOpenResult {
    pub device_label: String,
    pub conversation_label: String,
    pub message_label: String,
    pub conversation_state_dir: PathBuf,
    pub provider_storage_path: PathBuf,
    pub message_artifact_path: PathBuf,
    pub message_open_summary_path: PathBuf,
    pub plaintext_utf8: String,
    pub plaintext_len: usize,
    pub group_id_ref: String,
    pub member_count: usize,
    pub epoch_before: String,
    pub epoch_after: String,
    pub provider_storage_loaded: bool,
    pub provider_storage_written: bool,
    pub group_reloadable: bool,
    pub message_opened: bool,
}
