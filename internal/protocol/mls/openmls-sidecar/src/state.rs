pub use crate::paths::device_state_dir;
use crate::paths::{
    device_conversation_add_member_summary_path, device_conversation_join_summary_path,
    device_conversation_message_artifact_path, device_conversation_message_dir,
    device_conversation_message_manifest_path, device_conversation_message_open_summary_path,
    device_conversation_message_protect_summary_path, device_conversation_provider_storage_path,
    device_conversation_state_dir, device_conversation_summary_path,
    device_conversation_welcome_artifact_path, device_conversation_welcome_manifest_path,
    device_provider_storage_path, identity_prep_manifest_path, identity_state_path,
    identity_summary_path, public_bundle_keypackage_artifact_path, public_bundle_manifest_path,
    public_bundle_summary_path, signer_path,
};
use crate::provider::CarbonStackSidecarProvider;
use openmls::key_packages::KeyPackageIn;
use openmls::prelude::*;
use openmls::versions::ProtocolVersion;
use openmls_basic_credential::SignatureKeyPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

pub const CIPHERSUITE_LABEL: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

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

#[derive(Serialize)]
struct IdentityPrepManifest<'a> {
    manifest_version: &'a str,
    device_label: &'a str,
    state_scope: &'a str,
    identity_created: bool,
    provider_storage_written: bool,
    private_material_included: bool,
    warning: &'a str,
}

#[derive(Serialize)]
struct IdentitySummary<'a> {
    summary_version: &'a str,
    device_label: &'a str,
    ciphersuite: &'a str,
    identity_created: bool,
    public_identity_ref: &'a str,
    public_signature_key_len: usize,
    credential_type: &'a str,
    key_package_created: bool,
    public_bundle_available: bool,
    provider_storage_written: bool,
    private_material_included: bool,
}

#[derive(Serialize)]
struct IdentityState<'a> {
    state_version: &'a str,
    device_label: &'a str,
    state_scope: &'a str,
    identity_created: bool,
    signer_file: &'a str,
    identity_summary_file: &'a str,
    provider_storage_written: bool,
    key_package_created: bool,
    public_bundle_available: bool,
    private_material_included: bool,
    warning: &'a str,
}

#[derive(Deserialize)]
struct IdentitySummaryRead {
    device_label: String,
    identity_created: bool,
    public_identity_ref: String,
    provider_storage_written: bool,
    public_bundle_available: bool,
}

#[derive(Deserialize)]
struct IdentityStateRead {
    device_label: String,
    identity_created: bool,
    provider_storage_written: bool,
    public_bundle_available: bool,
}
pub fn create_dev_identity(device_label: &str) -> io::Result<IdentityCreateResult> {
    let state_dir = device_state_dir(device_label);
    let prep_manifest_path = identity_prep_manifest_path(device_label);
    let identity_summary_path = identity_summary_path(device_label);
    let identity_state_path = identity_state_path(device_label);
    let signer_path = signer_path(device_label);

    if prep_manifest_path.exists()
        || identity_summary_path.exists()
        || identity_state_path.exists()
        || signer_path.exists()
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "identity state already exists",
        ));
    }

    fs::create_dir_all(&state_dir)?;

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let credential = BasicCredential::new(device_label.as_bytes().to_vec());

    let signer = SignatureKeyPair::new(ciphersuite.into()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("signer create failed: {err:?}"),
        )
    })?;

    let public_signature_key = signer.to_public_vec();

    let _credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: public_signature_key.clone().into(),
    };

    let public_identity_ref = public_identity_ref(&public_signature_key);

    write_json_file(
        &prep_manifest_path,
        &IdentityPrepManifest {
            manifest_version: "identity-prep/v1",
            device_label,
            state_scope: "dev-local-sidecar-state",
            identity_created: true,
            provider_storage_written: false,
            private_material_included: false,
            warning: "dev identity created; prep manifest is non-secret and does not contain signer material",
        },
    )?;

    write_json_file(&signer_path, &signer)?;

    write_json_file(
        &identity_summary_path,
        &IdentitySummary {
            summary_version: "identity-summary/v0",
            device_label,
            ciphersuite: CIPHERSUITE_LABEL,
            identity_created: true,
            public_identity_ref: &public_identity_ref,
            public_signature_key_len: public_signature_key.len(),
            credential_type: "BasicCredential",
            key_package_created: false,
            public_bundle_available: false,
            provider_storage_written: false,
            private_material_included: false,
        },
    )?;

    write_json_file(
        &identity_state_path,
        &IdentityState {
            state_version: "identity-state/v0",
            device_label,
            state_scope: "dev-local-sidecar-state",
            identity_created: true,
            signer_file: "signer.json",
            identity_summary_file: "identity-summary.json",
            provider_storage_written: false,
            key_package_created: false,
            public_bundle_available: false,
            private_material_included: false,
            warning: "dev-only identity state; signer.json is secret-bearing and must not be printed or committed",
        },
    )?;

    Ok(IdentityCreateResult {
        device_label: device_label.to_string(),
        state_dir,
        prep_manifest_path,
        identity_summary_path,
        identity_state_path,
        signer_path,
        public_identity_ref,
        public_signature_key_len: public_signature_key.len(),
    })
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

pub fn load_dev_identity_status(device_label: &str) -> io::Result<IdentityStatusResult> {
    let state_dir = device_state_dir(device_label);
    let identity_summary_path = identity_summary_path(device_label);
    let identity_state_path = identity_state_path(device_label);
    let signer_path = signer_path(device_label);

    if !state_dir.exists()
        || !identity_summary_path.exists()
        || !identity_state_path.exists()
        || !signer_path.exists()
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "identity state is missing",
        ));
    }

    let signer: SignatureKeyPair = read_json_file(&signer_path).map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("signer load failed: {err}"))
    })?;

    let summary: IdentitySummaryRead = read_json_file(&identity_summary_path).map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("identity summary load failed: {err}"),
        )
    })?;

    let state: IdentityStateRead = read_json_file(&identity_state_path).map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("identity state load failed: {err}"),
        )
    })?;

    let public_signature_key = signer.to_public_vec();
    let computed_public_identity_ref = public_identity_ref(&public_signature_key);

    if summary.public_identity_ref != computed_public_identity_ref {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "identity summary public reference does not match signer",
        ));
    }

    if summary.device_label != device_label || state.device_label != device_label {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "identity state device label mismatch",
        ));
    }

    if !summary.identity_created || !state.identity_created {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "identity state does not report identity_created",
        ));
    }

    Ok(IdentityStatusResult {
        device_label: device_label.to_string(),
        state_dir,
        identity_summary_path,
        identity_state_path,
        signer_path,
        public_identity_ref: computed_public_identity_ref,
        public_signature_key_len: public_signature_key.len(),
        identity_created: true,
        provider_storage_written: summary.provider_storage_written
            || state.provider_storage_written,
        public_bundle_available: summary.public_bundle_available || state.public_bundle_available,
    })
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> io::Result<T> {
    let file = File::open(path)?;
    serde_json::from_reader(file).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("json read failed: {err}"),
        )
    })
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

#[derive(Serialize)]
struct PublicBundleSummary<'a> {
    summary_version: &'a str,
    device_label: &'a str,
    ciphersuite: &'a str,
    credential_type: &'a str,
    public_identity_ref: &'a str,
    public_signature_key_len: usize,
    key_package_created: bool,
    key_package_ref: &'a str,
    key_package_hash_len: usize,
    key_package_artifact_written: bool,
    key_package_artifact_path: Option<&'a str>,
    key_package_artifact_sha256: Option<&'a str>,
    key_package_artifact_size_bytes: Option<usize>,
    public_bundle_manifest_written: bool,
    public_bundle_manifest_path: Option<&'a str>,
    public_bundle_available: bool,
    provider_storage_written: bool,
    private_material_included: bool,
    warning: &'a str,
}

#[derive(Serialize)]
struct PublicBundleManifest<'a> {
    manifest_version: &'a str,
    device_label: &'a str,
    state_scope: &'a str,
    ciphersuite: &'a str,
    credential_type: &'a str,
    public_identity_ref: &'a str,
    public_signature_key_len: usize,
    key_package_ref: &'a str,
    key_package_hash_len: usize,
    key_package_artifact: &'a str,
    key_package_artifact_sha256: &'a str,
    key_package_artifact_size_bytes: usize,
    provider_storage_written: bool,
    private_material_included: bool,
    warning: &'a str,
}

pub fn export_dev_public_bundle_summary(
    device_label: &str,
    write_artifact: bool,
) -> io::Result<PublicBundleExportResult> {
    let status = load_dev_identity_status(device_label)?;

    let signer: SignatureKeyPair = read_json_file(&status.signer_path).map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("signer load failed: {err}"))
    })?;

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let credential = BasicCredential::new(device_label.as_bytes().to_vec());

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };

    let provider = CarbonStackSidecarProvider::default();

    let key_package_bundle = KeyPackage::builder()
        .build(ciphersuite, &provider, &signer, credential_with_key)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("key package build failed: {err:?}"),
            )
        })?;

    let key_package = key_package_bundle.key_package().clone();

    let key_package_hash = key_package.hash_ref(provider.crypto()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("key package hash failed: {err:?}"),
        )
    })?;

    let key_package_hash_bytes = key_package_hash.as_slice();
    let key_package_ref = format!("sha256:{}", hex::encode(key_package_hash_bytes));

    let public_bundle_summary_path = public_bundle_summary_path(device_label);
    let key_package_artifact_path = public_bundle_keypackage_artifact_path(device_label);
    let public_bundle_manifest_path = public_bundle_manifest_path(device_label);
    let provider_storage_path = device_provider_storage_path(device_label);

    if provider_storage_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "device provider storage already exists: {}",
                provider_storage_path.display()
            ),
        ));
    }

    provider.save_storage_to_path(&provider_storage_path)?;
    let provider_storage_written = true;

    let mut key_package_artifact_written = false;
    let mut public_bundle_manifest_written = false;
    let mut key_package_artifact_sha256: Option<String> = None;
    let mut key_package_artifact_size_bytes: Option<usize> = None;
    let mut key_package_artifact_path_string: Option<String> = None;
    let mut public_bundle_manifest_path_string: Option<String> = None;

    if write_artifact {
        if key_package_artifact_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "KeyPackage artifact already exists: {}",
                    key_package_artifact_path.display()
                ),
            ));
        }

        if public_bundle_manifest_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "public bundle manifest already exists: {}",
                    public_bundle_manifest_path.display()
                ),
            ));
        }

        let key_package_bytes = key_package.tls_serialize_detached().map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("key package TLS serialization failed: {err:?}"),
            )
        })?;

        let artifact_digest = Sha256::digest(&key_package_bytes);
        let artifact_sha256 = format!("sha256:{}", hex::encode(artifact_digest));
        let artifact_size = key_package_bytes.len();

        fs::write(&key_package_artifact_path, &key_package_bytes)?;

        let artifact_file_name = "public-bundle.keypackage.bin";
        let manifest_file_name = "public-bundle-manifest.json";

        write_json_file(
            &public_bundle_manifest_path,
            &PublicBundleManifest {
                manifest_version: "public-bundle-manifest/v0",
                device_label,
                state_scope: "dev-local-sidecar-state",
                ciphersuite: CIPHERSUITE_LABEL,
                credential_type: "BasicCredential",
                public_identity_ref: &status.public_identity_ref,
                public_signature_key_len: status.public_signature_key_len,
                key_package_ref: &key_package_ref,
                key_package_hash_len: key_package_hash_bytes.len(),
                key_package_artifact: artifact_file_name,
                key_package_artifact_sha256: &artifact_sha256,
                key_package_artifact_size_bytes: artifact_size,
                provider_storage_written,
                private_material_included: false,
                warning: "dev-only serialized public KeyPackage artifact with dev provider storage; not final CarbonStack onboarding material",
            },
        )?;

        key_package_artifact_written = true;
        public_bundle_manifest_written = true;
        key_package_artifact_sha256 = Some(artifact_sha256);
        key_package_artifact_size_bytes = Some(artifact_size);
        key_package_artifact_path_string =
            Some(key_package_artifact_path.to_string_lossy().to_string());
        public_bundle_manifest_path_string =
            Some(public_bundle_manifest_path.to_string_lossy().to_string());

        let _ = manifest_file_name;
    }

    write_json_file(
        &public_bundle_summary_path,
        &PublicBundleSummary {
            summary_version: "public-bundle-summary/v0",
            device_label,
            ciphersuite: CIPHERSUITE_LABEL,
            credential_type: "BasicCredential",
            public_identity_ref: &status.public_identity_ref,
            public_signature_key_len: status.public_signature_key_len,
            key_package_created: true,
            key_package_ref: &key_package_ref,
            key_package_hash_len: key_package_hash_bytes.len(),
            key_package_artifact_written,
            key_package_artifact_path: key_package_artifact_path_string.as_deref(),
            key_package_artifact_sha256: key_package_artifact_sha256.as_deref(),
            key_package_artifact_size_bytes,
            public_bundle_manifest_written,
            public_bundle_manifest_path: public_bundle_manifest_path_string.as_deref(),
            public_bundle_available: true,
            provider_storage_written,
            private_material_included: false,
            warning: if write_artifact {
                "dev-only public bundle summary with serialized public KeyPackage artifact and dev provider storage; not final CarbonStack onboarding material"
            } else {
                "dev-only public bundle summary; full serialized KeyPackage artifact is not exported in this rung"
            },
        },
    )?;

    Ok(PublicBundleExportResult {
        device_label: device_label.to_string(),
        state_dir: status.state_dir,
        public_bundle_summary_path,
        public_identity_ref: status.public_identity_ref,
        public_signature_key_len: status.public_signature_key_len,
        key_package_ref,
        key_package_hash_len: key_package_hash_bytes.len(),
        key_package_artifact_written,
        key_package_artifact_path: key_package_artifact_path_string,
        key_package_artifact_sha256,
        key_package_artifact_size_bytes,
        public_bundle_manifest_written,
        public_bundle_manifest_path: public_bundle_manifest_path_string,
        provider_storage_written,
    })
}
fn public_identity_ref(public_signature_key: &[u8]) -> String {
    let digest = Sha256::digest(public_signature_key);
    format!("sha256:{}", hex::encode(digest))
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, value)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("json write failed: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::{DEV_SCOPE, STATE_ROOT};

    #[test]
    fn device_state_dir_uses_dev_scope() {
        let path = device_state_dir("carbonstack-alice-device");
        let rendered = path.to_string_lossy();

        assert!(rendered.contains(STATE_ROOT));
        assert!(rendered.contains(DEV_SCOPE));
        assert!(rendered.contains("devices"));
        assert!(rendered.contains("carbonstack-alice-device"));
    }

    #[test]
    fn identity_prep_manifest_uses_expected_filename() {
        let path = identity_prep_manifest_path("carbonstack-alice-device");
        assert!(path.ends_with("identity-prep.json"));
    }

    #[test]
    fn identity_summary_uses_expected_filename() {
        let path = identity_summary_path("carbonstack-alice-device");
        assert!(path.ends_with("identity-summary.json"));
    }

    #[test]
    fn signer_uses_expected_filename() {
        let path = signer_path("carbonstack-alice-device");
        assert!(path.ends_with("signer.json"));
    }
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

#[derive(Serialize)]
struct ConversationSummary<'a> {
    summary_version: &'a str,
    conversation_label: &'a str,
    creator_device_label: &'a str,
    state_scope: &'a str,
    ciphersuite: &'a str,
    group_id_ref: &'a str,
    group_id_len: usize,
    member_count: usize,
    epoch: &'a str,
    conversation_created: bool,
    provider_storage_written: bool,
    group_reloadable: bool,
    provider_storage_file: &'a str,
    private_material_included: bool,
    warning: &'a str,
}

pub fn create_dev_conversation(
    device_label: &str,
    conversation_label: &str,
) -> io::Result<ConversationCreateResult> {
    let status = load_dev_identity_status(device_label)?;

    let conversation_state_dir = device_conversation_state_dir(device_label, conversation_label);
    let conversation_summary_path =
        device_conversation_summary_path(device_label, conversation_label);
    let provider_storage_path =
        device_conversation_provider_storage_path(device_label, conversation_label);

    if conversation_summary_path.exists() || provider_storage_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "conversation state already exists",
        ));
    }

    fs::create_dir_all(&conversation_state_dir)?;

    let signer: SignatureKeyPair = read_json_file(&status.signer_path).map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("signer load failed: {err}"))
    })?;

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let credential = BasicCredential::new(device_label.as_bytes().to_vec());

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };

    let provider = CarbonStackSidecarProvider::default();

    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();

    let group_id_bytes = format!("carbonstack-openmls-dev-conversation:{conversation_label}");
    let group_id = GroupId::from_slice(group_id_bytes.as_bytes());

    let _group = MlsGroup::new_with_group_id(
        &provider,
        &signer,
        &create_config,
        group_id.clone(),
        credential_with_key,
    )
    .map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("conversation group create failed: {err:?}"),
        )
    })?;

    provider.save_storage_to_path(&provider_storage_path)?;

    let mut reloaded_provider = CarbonStackSidecarProvider::default();
    reloaded_provider.load_storage_from_path(&provider_storage_path)?;

    let reloaded_group = MlsGroup::load(reloaded_provider.storage(), &group_id)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("conversation group reload failed: {err:?}"),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "conversation group not found after provider storage reload",
            )
        })?;

    let group_id_digest = Sha256::digest(group_id_bytes.as_bytes());
    let group_id_ref = format!("sha256:{}", hex::encode(group_id_digest));
    let epoch = format!("{:?}", reloaded_group.epoch());
    let member_count = reloaded_group.members().count();

    write_json_file(
        &conversation_summary_path,
        &ConversationSummary {
            summary_version: "conversation-summary/v0",
            conversation_label,
            creator_device_label: device_label,
            state_scope: "dev-local-sidecar-state",
            ciphersuite: CIPHERSUITE_LABEL,
            group_id_ref: &group_id_ref,
            group_id_len: group_id_bytes.as_bytes().len(),
            member_count,
            epoch: &epoch,
            conversation_created: true,
            provider_storage_written: true,
            group_reloadable: true,
            provider_storage_file: "provider-storage.json",
            private_material_included: false,
            warning: "dev-only OpenMLS conversation summary with reloadable dev provider storage; not production messaging or secure vault storage",
        },
    )?;

    Ok(ConversationCreateResult {
        device_label: device_label.to_string(),
        conversation_label: conversation_label.to_string(),
        conversation_state_dir,
        conversation_summary_path,
        provider_storage_path,
        group_id_ref,
        group_id_len: group_id_bytes.as_bytes().len(),
        member_count,
        epoch,
        provider_storage_written: true,
        group_reloadable: true,
    })
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

pub fn load_dev_conversation_status(
    device_label: &str,
    conversation_label: &str,
) -> io::Result<ConversationLoadCheckResult> {
    let _status = load_dev_identity_status(device_label)?;

    let conversation_state_dir = device_conversation_state_dir(device_label, conversation_label);
    let conversation_summary_path =
        device_conversation_summary_path(device_label, conversation_label);
    let provider_storage_path =
        device_conversation_provider_storage_path(device_label, conversation_label);

    if !conversation_summary_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "conversation summary is missing",
        ));
    }

    if !provider_storage_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "conversation provider storage is missing",
        ));
    }

    let group_id_bytes = format!("carbonstack-openmls-dev-conversation:{conversation_label}");
    let group_id = GroupId::from_slice(group_id_bytes.as_bytes());

    let mut provider = CarbonStackSidecarProvider::default();
    provider.load_storage_from_path(&provider_storage_path)?;

    let group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("conversation group reload failed: {err:?}"),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "conversation group not found in provider storage",
            )
        })?;

    let group_id_digest = Sha256::digest(group_id_bytes.as_bytes());
    let group_id_ref = format!("sha256:{}", hex::encode(group_id_digest));

    Ok(ConversationLoadCheckResult {
        device_label: device_label.to_string(),
        conversation_label: conversation_label.to_string(),
        conversation_state_dir,
        conversation_summary_path,
        provider_storage_path,
        group_id_ref,
        group_id_len: group_id_bytes.as_bytes().len(),
        member_count: group.members().count(),
        epoch: format!("{:?}", group.epoch()),
        provider_storage_loaded: true,
        group_reloadable: true,
    })
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

#[derive(Serialize)]
struct WelcomeManifest<'a> {
    manifest_version: &'a str,
    device_label: &'a str,
    conversation_label: &'a str,
    state_scope: &'a str,
    artifact_file: &'a str,
    artifact_sha256: &'a str,
    artifact_size_bytes: usize,
    member_keypackage_path_hint: &'a str,
    provider_storage_file: &'a str,
    private_material_included: bool,
    warning: &'a str,
}

#[derive(Serialize)]
struct AddMemberSummary<'a> {
    summary_version: &'a str,
    device_label: &'a str,
    conversation_label: &'a str,
    state_scope: &'a str,
    group_id_ref: &'a str,
    group_id_len: usize,
    provider_storage_loaded: bool,
    provider_storage_written: bool,
    group_reloadable: bool,
    member_added: bool,
    welcome_artifact_written: bool,
    pending_commit_merged: bool,
    member_count_before: usize,
    member_count_after: usize,
    epoch_before: &'a str,
    epoch_after: &'a str,
    welcome_artifact_file: &'a str,
    welcome_artifact_sha256: &'a str,
    welcome_artifact_size_bytes: usize,
    provider_storage_file: &'a str,
    private_material_included: bool,
    warning: &'a str,
}

fn validate_member_keypackage_path(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "member key package path is empty",
        ));
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");

    let forbidden = [
        "signer.json",
        "provider-storage.json",
        "conversation-summary.json",
        "identity-state.json",
        "identity-summary.json",
        "identity-prep.json",
        "public-bundle-summary.json",
        "public-bundle-manifest.json",
    ];

    if forbidden.iter().any(|blocked| *blocked == file_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing member key package path with forbidden file name: {file_name}"),
        ));
    }

    let metadata = fs::metadata(path)?;

    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "member key package path is not a file",
        ));
    }

    if metadata.len() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "member key package artifact is empty",
        ));
    }

    const MAX_KEYPACKAGE_ARTIFACT_BYTES: u64 = 1024 * 1024;

    if metadata.len() > MAX_KEYPACKAGE_ARTIFACT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "member key package artifact is too large",
        ));
    }

    Ok(())
}

pub fn add_dev_conversation_member(
    device_label: &str,
    conversation_label: &str,
    member_keypackage_path: &Path,
) -> io::Result<ConversationAddMemberResult> {
    let status = load_dev_identity_status(device_label)?;

    validate_member_keypackage_path(member_keypackage_path)?;

    let conversation_state_dir = device_conversation_state_dir(device_label, conversation_label);
    let conversation_summary_path =
        device_conversation_summary_path(device_label, conversation_label);
    let provider_storage_path =
        device_conversation_provider_storage_path(device_label, conversation_label);
    let welcome_artifact_path =
        device_conversation_welcome_artifact_path(device_label, conversation_label);
    let welcome_manifest_path =
        device_conversation_welcome_manifest_path(device_label, conversation_label);
    let add_member_summary_path =
        device_conversation_add_member_summary_path(device_label, conversation_label);

    if !conversation_summary_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "conversation summary is missing",
        ));
    }

    if !provider_storage_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "conversation provider storage is missing",
        ));
    }

    if welcome_artifact_path.exists()
        || welcome_manifest_path.exists()
        || add_member_summary_path.exists()
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "add-member output artifacts already exist",
        ));
    }

    let signer: SignatureKeyPair = read_json_file(&status.signer_path).map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("signer load failed: {err}"))
    })?;

    let mut provider = CarbonStackSidecarProvider::default();
    provider.load_storage_from_path(&provider_storage_path)?;

    let group_id_bytes = format!("carbonstack-openmls-dev-conversation:{conversation_label}");
    let group_id = GroupId::from_slice(group_id_bytes.as_bytes());

    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("conversation group reload failed: {err:?}"),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "conversation group not found in provider storage",
            )
        })?;

    let member_count_before = group.members().count();
    let epoch_before = format!("{:?}", group.epoch());

    let key_package_bytes = fs::read(member_keypackage_path)?;
    let mut key_package_slice = key_package_bytes.as_slice();

    let key_package_in = KeyPackageIn::tls_deserialize(&mut key_package_slice).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("member key package TLS deserialization failed: {err:?}"),
        )
    })?;

    let member_key_package = key_package_in
        .validate(provider.crypto(), ProtocolVersion::default())
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("member key package validation failed: {err:?}"),
            )
        })?;

    let (_commit_message, welcome_message, _group_info) = group
        .add_members(&provider, &signer, &[member_key_package])
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("conversation add-member failed: {err:?}"),
            )
        })?;

    if !matches!(welcome_message.body(), MlsMessageBodyOut::Welcome(_)) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "add_members did not return a Welcome message",
        ));
    }

    let welcome_bytes = welcome_message.to_bytes().map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Welcome message serialization failed: {err:?}"),
        )
    })?;

    let welcome_digest = Sha256::digest(&welcome_bytes);
    let welcome_sha256 = format!("sha256:{}", hex::encode(welcome_digest));
    let welcome_size = welcome_bytes.len();

    fs::write(&welcome_artifact_path, &welcome_bytes)?;

    group.merge_pending_commit(&provider).map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("merge pending commit failed: {err:?}"),
        )
    })?;

    let member_count_after = group.members().count();
    let epoch_after = format!("{:?}", group.epoch());

    provider.save_storage_to_path(&provider_storage_path)?;

    let member_keypackage_path_hint = member_keypackage_path.to_string_lossy();

    write_json_file(
        &welcome_manifest_path,
        &WelcomeManifest {
            manifest_version: "welcome-manifest/v0",
            device_label,
            conversation_label,
            state_scope: "dev-local-sidecar-state",
            artifact_file: "welcome.bin",
            artifact_sha256: &welcome_sha256,
            artifact_size_bytes: welcome_size,
            member_keypackage_path_hint: &member_keypackage_path_hint,
            provider_storage_file: "provider-storage.json",
            private_material_included: false,
            warning: "dev-only OpenMLS Welcome carrier artifact; not production onboarding format",
        },
    )?;

    write_json_file(
        &add_member_summary_path,
        &AddMemberSummary {
            summary_version: "add-member-summary/v0",
            device_label,
            conversation_label,
            state_scope: "dev-local-sidecar-state",
            group_id_ref: &format!(
                "sha256:{}",
                hex::encode(Sha256::digest(group_id_bytes.as_bytes()))
            ),
            group_id_len: group_id_bytes.as_bytes().len(),
            provider_storage_loaded: true,
            provider_storage_written: true,
            group_reloadable: true,
            member_added: true,
            welcome_artifact_written: true,
            pending_commit_merged: true,
            member_count_before,
            member_count_after,
            epoch_before: &epoch_before,
            epoch_after: &epoch_after,
            welcome_artifact_file: "welcome.bin",
            welcome_artifact_sha256: &welcome_sha256,
            welcome_artifact_size_bytes: welcome_size,
            provider_storage_file: "provider-storage.json",
            private_material_included: false,
            warning: "dev-only OpenMLS add-member summary; not production membership UX or secure storage",
        },
    )?;

    let group_id_ref = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(group_id_bytes.as_bytes()))
    );

    Ok(ConversationAddMemberResult {
        device_label: device_label.to_string(),
        conversation_label: conversation_label.to_string(),
        member_keypackage_path: member_keypackage_path.to_path_buf(),
        conversation_state_dir,
        conversation_summary_path,
        provider_storage_path,
        welcome_artifact_path,
        welcome_manifest_path,
        add_member_summary_path,
        group_id_ref,
        group_id_len: group_id_bytes.as_bytes().len(),
        provider_storage_loaded: true,
        provider_storage_written: true,
        group_reloadable: true,
        member_added: true,
        welcome_artifact_written: true,
        pending_commit_merged: true,
        member_count_before,
        member_count_after,
        epoch_before,
        epoch_after,
        welcome_artifact_sha256: welcome_sha256,
        welcome_artifact_size_bytes: welcome_size,
    })
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

#[derive(Serialize)]
struct JoinedConversationSummary<'a> {
    summary_version: &'a str,
    device_label: &'a str,
    conversation_label: &'a str,
    state_scope: &'a str,
    group_id_ref: &'a str,
    group_id_len: usize,
    provider_storage_written: bool,
    provider_storage_loaded: bool,
    group_reloadable: bool,
    joined: bool,
    member_count: usize,
    epoch: &'a str,
    provider_storage_file: &'a str,
    private_material_included: bool,
    warning: &'a str,
}

#[derive(Serialize)]
struct JoinSummary<'a> {
    summary_version: &'a str,
    device_label: &'a str,
    conversation_label: &'a str,
    state_scope: &'a str,
    welcome_artifact_path_hint: &'a str,
    group_id_ref: &'a str,
    group_id_len: usize,
    provider_storage_written: bool,
    provider_storage_loaded: bool,
    group_reloadable: bool,
    joined: bool,
    member_count: usize,
    epoch: &'a str,
    provider_storage_file: &'a str,
    private_material_included: bool,
    warning: &'a str,
}

fn validate_welcome_artifact_path(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Welcome artifact path is empty",
        ));
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");

    let forbidden = [
        "signer.json",
        "provider-storage.json",
        "conversation-summary.json",
        "identity-state.json",
        "identity-summary.json",
        "identity-prep.json",
        "public-bundle-summary.json",
        "public-bundle-manifest.json",
        "public-bundle.keypackage.bin",
        "add-member-summary.json",
        "welcome-manifest.json",
    ];

    if forbidden.iter().any(|blocked| *blocked == file_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing Welcome artifact path with forbidden file name: {file_name}"),
        ));
    }

    let metadata = fs::metadata(path)?;

    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Welcome artifact path is not a file",
        ));
    }

    if metadata.len() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Welcome artifact is empty",
        ));
    }

    const MAX_WELCOME_ARTIFACT_BYTES: u64 = 1024 * 1024;

    if metadata.len() > MAX_WELCOME_ARTIFACT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Welcome artifact is too large",
        ));
    }

    Ok(())
}

pub fn join_dev_conversation(
    device_label: &str,
    conversation_label: &str,
    welcome_artifact_path: &Path,
) -> io::Result<ConversationJoinResult> {
    let _status = load_dev_identity_status(device_label)?;

    validate_welcome_artifact_path(welcome_artifact_path)?;

    let conversation_state_dir = device_conversation_state_dir(device_label, conversation_label);
    let conversation_summary_path =
        device_conversation_summary_path(device_label, conversation_label);
    let provider_storage_path =
        device_conversation_provider_storage_path(device_label, conversation_label);
    let join_summary_path = device_conversation_join_summary_path(device_label, conversation_label);

    if conversation_state_dir.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "joined conversation state already exists",
        ));
    }

    fs::create_dir_all(&conversation_state_dir)?;

    let welcome_bytes = fs::read(welcome_artifact_path)?;
    let mut welcome_slice = welcome_bytes.as_slice();

    let mls_message_in = MlsMessageIn::tls_deserialize(&mut welcome_slice).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Welcome carrier deserialization failed: {err:?}"),
        )
    })?;

    let welcome = match mls_message_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Welcome artifact did not contain an MLS Welcome message",
            ));
        }
    };

    let mut provider = CarbonStackSidecarProvider::default();
    let device_provider_storage_path = device_provider_storage_path(device_label);

    if !device_provider_storage_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "device provider storage is missing; export a public bundle artifact before joining",
        ));
    }

    provider.load_storage_from_path(&device_provider_storage_path)?;

    let join_config = MlsGroupJoinConfig::builder().build();

    let staged_welcome = StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("conversation join staging failed: {err:?}"),
            )
        })?;

    let group = staged_welcome.into_group(&provider).map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("conversation join into_group failed: {err:?}"),
        )
    })?;

    let member_count = group.members().count();
    let epoch = format!("{:?}", group.epoch());
    let group_id_bytes = group.group_id().as_slice().to_vec();
    let group_id_ref = format!("sha256:{}", hex::encode(Sha256::digest(&group_id_bytes)));
    let group_id_len = group_id_bytes.len();

    provider.save_storage_to_path(&provider_storage_path)?;

    let mut reloaded_provider = CarbonStackSidecarProvider::default();
    reloaded_provider.load_storage_from_path(&provider_storage_path)?;

    let reloaded_group = MlsGroup::load(reloaded_provider.storage(), group.group_id())
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("joined conversation group reload failed: {err:?}"),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "joined conversation group not found in provider storage",
            )
        })?;

    let reloaded_member_count = reloaded_group.members().count();
    let reloaded_epoch = format!("{:?}", reloaded_group.epoch());

    let welcome_artifact_path_hint = welcome_artifact_path.to_string_lossy();

    write_json_file(
        &conversation_summary_path,
        &JoinedConversationSummary {
            summary_version: "joined-conversation-summary/v0",
            device_label,
            conversation_label,
            state_scope: "dev-local-sidecar-state",
            group_id_ref: &group_id_ref,
            group_id_len,
            provider_storage_written: true,
            provider_storage_loaded: true,
            group_reloadable: true,
            joined: true,
            member_count: reloaded_member_count,
            epoch: &reloaded_epoch,
            provider_storage_file: "provider-storage.json",
            private_material_included: false,
            warning: "dev-only OpenMLS joined conversation summary; not production secure storage",
        },
    )?;

    write_json_file(
        &join_summary_path,
        &JoinSummary {
            summary_version: "join-summary/v0",
            device_label,
            conversation_label,
            state_scope: "dev-local-sidecar-state",
            welcome_artifact_path_hint: &welcome_artifact_path_hint,
            group_id_ref: &group_id_ref,
            group_id_len,
            provider_storage_written: true,
            provider_storage_loaded: true,
            group_reloadable: true,
            joined: true,
            member_count: reloaded_member_count,
            epoch: &reloaded_epoch,
            provider_storage_file: "provider-storage.json",
            private_material_included: false,
            warning: "dev-only OpenMLS join summary; Welcome consumed locally but not printed",
        },
    )?;

    Ok(ConversationJoinResult {
        device_label: device_label.to_string(),
        conversation_label: conversation_label.to_string(),
        welcome_artifact_path: welcome_artifact_path.to_path_buf(),
        conversation_state_dir,
        conversation_summary_path,
        provider_storage_path,
        join_summary_path,
        group_id_ref,
        group_id_len,
        provider_storage_written: true,
        provider_storage_loaded: true,
        group_reloadable: true,
        joined: true,
        member_count,
        epoch,
    })
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

#[derive(Serialize)]
struct MessageManifest<'a> {
    summary_version: &'a str,
    device_label: &'a str,
    conversation_label: &'a str,
    message_label: &'a str,
    state_scope: &'a str,
    group_id_ref: &'a str,
    member_count: usize,
    epoch_before: &'a str,
    epoch_after: &'a str,
    message_artifact_file: &'a str,
    message_artifact_sha256: &'a str,
    message_artifact_size_bytes: usize,
    provider_storage_loaded: bool,
    provider_storage_written: bool,
    group_reloadable: bool,
    private_material_included: bool,
    warning: &'a str,
}

#[derive(Serialize)]
struct MessageProtectSummary<'a> {
    summary_version: &'a str,
    device_label: &'a str,
    conversation_label: &'a str,
    message_label: &'a str,
    state_scope: &'a str,
    group_id_ref: &'a str,
    member_count: usize,
    epoch_before: &'a str,
    epoch_after: &'a str,
    message_protected: bool,
    protected_message_written: bool,
    message_artifact_file: &'a str,
    message_artifact_sha256: &'a str,
    message_artifact_size_bytes: usize,
    provider_storage_loaded: bool,
    provider_storage_written: bool,
    group_reloadable: bool,
    private_material_included: bool,
    warning: &'a str,
}

#[derive(Serialize)]
struct MessageOpenSummary<'a> {
    summary_version: &'a str,
    device_label: &'a str,
    conversation_label: &'a str,
    message_label: &'a str,
    state_scope: &'a str,
    group_id_ref: &'a str,
    member_count: usize,
    epoch_before: &'a str,
    epoch_after: &'a str,
    message_opened: bool,
    message_artifact_path_hint: &'a str,
    plaintext_len: usize,
    provider_storage_loaded: bool,
    provider_storage_written: bool,
    group_reloadable: bool,
    private_material_included: bool,
    warning: &'a str,
}

pub fn validate_message_label(label: &str) -> io::Result<()> {
    if label.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message label is empty",
        ));
    }

    if label.len() > 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message label is too long",
        ));
    }

    if label.starts_with('.') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message label must not start with dot",
        ));
    }

    if label.contains('/') || label.contains('\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message label must not contain path separators",
        ));
    }

    if !label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message label must contain only ASCII letters, numbers, hyphen, or underscore",
        ));
    }

    let lower = label.to_ascii_lowercase();
    let reserved = [
        "signer",
        "signer-json",
        "provider-storage",
        "provider-storage-json",
        "identity-state",
        "identity-summary",
        "identity-prep",
        "public-bundle",
        "public-bundle-summary",
        "public-bundle-manifest",
        "public-bundle-keypackage",
        "welcome",
        "welcome-manifest",
        "add-member-summary",
        "join-summary",
        "conversation-summary",
        "message-manifest",
        "message-protect-summary",
        "message-open-summary",
        "application-message",
        "con",
        "prn",
        "aux",
        "nul",
        "com1",
        "com2",
        "com3",
        "com4",
        "com5",
        "com6",
        "com7",
        "com8",
        "com9",
        "lpt1",
        "lpt2",
        "lpt3",
        "lpt4",
        "lpt5",
        "lpt6",
        "lpt7",
        "lpt8",
        "lpt9",
    ];

    if reserved.contains(&lower.as_str()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message label is reserved",
        ));
    }

    Ok(())
}
fn validate_plaintext_for_dev(plaintext: &str) -> io::Result<()> {
    if plaintext.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "plaintext is empty",
        ));
    }

    const MAX_DEV_PLAINTEXT_BYTES: usize = 4096;

    if plaintext.as_bytes().len() > MAX_DEV_PLAINTEXT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "plaintext is too large for dev message-protect",
        ));
    }

    Ok(())
}

fn validate_message_artifact_path(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message artifact path is empty",
        ));
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");

    let forbidden = [
        "signer.json",
        "provider-storage.json",
        "conversation-summary.json",
        "identity-state.json",
        "identity-summary.json",
        "identity-prep.json",
        "public-bundle-summary.json",
        "public-bundle-manifest.json",
        "public-bundle.keypackage.bin",
        "welcome.bin",
        "welcome-manifest.json",
        "add-member-summary.json",
        "join-summary.json",
    ];

    if forbidden.iter().any(|blocked| *blocked == file_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing message artifact path with forbidden file name: {file_name}"),
        ));
    }

    let metadata = fs::metadata(path)?;

    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message artifact path is not a file",
        ));
    }

    if metadata.len() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message artifact is empty",
        ));
    }

    const MAX_MESSAGE_ARTIFACT_BYTES: u64 = 1024 * 1024;

    if metadata.len() > MAX_MESSAGE_ARTIFACT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message artifact is too large",
        ));
    }

    Ok(())
}

pub fn protect_dev_message(
    device_label: &str,
    conversation_label: &str,
    message_label: &str,
    plaintext: &str,
) -> io::Result<MessageProtectResult> {
    validate_message_label(message_label)?;
    validate_plaintext_for_dev(plaintext)?;

    let status = load_dev_identity_status(device_label)?;

    let signer: SignatureKeyPair = read_json_file(&status.signer_path).map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("signer load failed: {err}"))
    })?;

    let conversation_state_dir = device_conversation_state_dir(device_label, conversation_label);
    let provider_storage_path =
        device_conversation_provider_storage_path(device_label, conversation_label);

    if !provider_storage_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "conversation provider storage is missing",
        ));
    }

    let message_dir =
        device_conversation_message_dir(device_label, conversation_label, message_label);
    let message_artifact_path =
        device_conversation_message_artifact_path(device_label, conversation_label, message_label);
    let message_manifest_path =
        device_conversation_message_manifest_path(device_label, conversation_label, message_label);
    let message_protect_summary_path = device_conversation_message_protect_summary_path(
        device_label,
        conversation_label,
        message_label,
    );

    if message_dir.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "message artifact state already exists",
        ));
    }

    fs::create_dir_all(&message_dir)?;

    let mut provider = CarbonStackSidecarProvider::default();
    provider.load_storage_from_path(&provider_storage_path)?;

    let group_id_bytes = format!("carbonstack-openmls-dev-conversation:{conversation_label}");
    let group_id = GroupId::from_slice(group_id_bytes.as_bytes());

    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("conversation group load failed: {err:?}"),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "conversation group not found in provider storage",
            )
        })?;

    let epoch_before = format!("{:?}", group.epoch());
    let member_count = group.members().count();
    let group_id_bytes = group.group_id().as_slice().to_vec();
    let group_id_ref = format!("sha256:{}", hex::encode(Sha256::digest(&group_id_bytes)));

    let message_out = group
        .create_message(&provider, &signer, plaintext.as_bytes())
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("message protect failed: {err:?}"),
            )
        })?;

    let message_bytes = message_out.to_bytes().map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("message serialization failed: {err:?}"),
        )
    })?;

    fs::write(&message_artifact_path, &message_bytes)?;

    let message_artifact_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&message_bytes)));
    let message_artifact_size_bytes = message_bytes.len();

    provider.save_storage_to_path(&provider_storage_path)?;

    let mut reloaded_provider = CarbonStackSidecarProvider::default();
    reloaded_provider.load_storage_from_path(&provider_storage_path)?;

    let reloaded_group = MlsGroup::load(reloaded_provider.storage(), &group_id)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("message protect reload failed: {err:?}"),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "message protect group not found after storage save",
            )
        })?;

    let epoch_after = format!("{:?}", reloaded_group.epoch());

    write_json_file(
        &message_manifest_path,
        &MessageManifest {
            summary_version: "message-manifest/v0",
            device_label,
            conversation_label,
            message_label,
            state_scope: "dev-local-sidecar-state",
            group_id_ref: &group_id_ref,
            member_count,
            epoch_before: &epoch_before,
            epoch_after: &epoch_after,
            message_artifact_file: "application-message.bin",
            message_artifact_sha256: &message_artifact_sha256,
            message_artifact_size_bytes,
            provider_storage_loaded: true,
            provider_storage_written: true,
            group_reloadable: true,
            private_material_included: false,
            warning: "dev-only protected MLS application message artifact; raw bytes not printed",
        },
    )?;

    write_json_file(
        &message_protect_summary_path,
        &MessageProtectSummary {
            summary_version: "message-protect-summary/v0",
            device_label,
            conversation_label,
            message_label,
            state_scope: "dev-local-sidecar-state",
            group_id_ref: &group_id_ref,
            member_count,
            epoch_before: &epoch_before,
            epoch_after: &epoch_after,
            message_protected: true,
            protected_message_written: true,
            message_artifact_file: "application-message.bin",
            message_artifact_sha256: &message_artifact_sha256,
            message_artifact_size_bytes,
            provider_storage_loaded: true,
            provider_storage_written: true,
            group_reloadable: true,
            private_material_included: false,
            warning: "dev-only message protect summary; plaintext not stored in summary",
        },
    )?;

    Ok(MessageProtectResult {
        device_label: device_label.to_string(),
        conversation_label: conversation_label.to_string(),
        message_label: message_label.to_string(),
        conversation_state_dir,
        provider_storage_path,
        message_dir,
        message_artifact_path,
        message_manifest_path,
        message_protect_summary_path,
        message_artifact_sha256,
        message_artifact_size_bytes,
        group_id_ref,
        member_count,
        epoch_before,
        epoch_after,
        provider_storage_loaded: true,
        provider_storage_written: true,
        group_reloadable: true,
        message_protected: true,
        protected_message_written: true,
    })
}

pub fn open_dev_message(
    device_label: &str,
    conversation_label: &str,
    message_label: &str,
    message_artifact_path: &Path,
) -> io::Result<MessageOpenResult> {
    validate_message_label(message_label)?;
    validate_message_artifact_path(message_artifact_path)?;

    let conversation_state_dir = device_conversation_state_dir(device_label, conversation_label);
    let provider_storage_path =
        device_conversation_provider_storage_path(device_label, conversation_label);

    if !provider_storage_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "device conversation provider storage is missing",
        ));
    }

    let message_open_summary_path = device_conversation_message_open_summary_path(
        device_label,
        conversation_label,
        message_label,
    );

    if let Some(parent) = message_open_summary_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let message_bytes = fs::read(message_artifact_path)?;
    let message_in = MlsMessageIn::tls_deserialize_exact_bytes(&message_bytes).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message artifact deserialization failed: {err:?}"),
        )
    })?;

    let protocol_message = message_in.try_into_protocol_message().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message artifact was not a protocol message: {err:?}"),
        )
    })?;

    let mut provider = CarbonStackSidecarProvider::default();
    provider.load_storage_from_path(&provider_storage_path)?;

    let group_id_bytes = format!("carbonstack-openmls-dev-conversation:{conversation_label}");
    let group_id = GroupId::from_slice(group_id_bytes.as_bytes());

    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("joined conversation group load failed: {err:?}"),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "joined conversation group not found in provider storage",
            )
        })?;

    let epoch_before = format!("{:?}", group.epoch());

    let processed_message = group
        .process_message(&provider, protocol_message)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("message open failed: {err:?}"),
            )
        })?;

    let plaintext_bytes = match processed_message.into_content() {
        ProcessedMessageContent::ApplicationMessage(application_message) => {
            application_message.into_bytes()
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "processed message was not an application message",
            ));
        }
    };

    let plaintext_utf8 = String::from_utf8(plaintext_bytes.clone()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("application plaintext was not UTF-8: {err:?}"),
        )
    })?;

    let plaintext_len = plaintext_bytes.len();

    let member_count = group.members().count();
    let group_id_bytes = group.group_id().as_slice().to_vec();
    let group_id_ref = format!("sha256:{}", hex::encode(Sha256::digest(&group_id_bytes)));

    provider.save_storage_to_path(&provider_storage_path)?;

    let mut reloaded_provider = CarbonStackSidecarProvider::default();
    reloaded_provider.load_storage_from_path(&provider_storage_path)?;

    let reloaded_group = MlsGroup::load(reloaded_provider.storage(), &group_id)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("message open reload failed: {err:?}"),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "message open group not found after storage save",
            )
        })?;

    let epoch_after = format!("{:?}", reloaded_group.epoch());
    let message_artifact_path_hint = message_artifact_path.to_string_lossy();

    write_json_file(
        &message_open_summary_path,
        &MessageOpenSummary {
            summary_version: "message-open-summary/v0",
            device_label,
            conversation_label,
            message_label,
            state_scope: "dev-local-sidecar-state",
            group_id_ref: &group_id_ref,
            member_count,
            epoch_before: &epoch_before,
            epoch_after: &epoch_after,
            message_opened: true,
            message_artifact_path_hint: &message_artifact_path_hint,
            plaintext_len,
            provider_storage_loaded: true,
            provider_storage_written: true,
            group_reloadable: true,
            private_material_included: false,
            warning: "dev-only message open summary; plaintext returned only in bounded stdout",
        },
    )?;

    Ok(MessageOpenResult {
        device_label: device_label.to_string(),
        conversation_label: conversation_label.to_string(),
        message_label: message_label.to_string(),
        conversation_state_dir,
        provider_storage_path,
        message_artifact_path: message_artifact_path.to_path_buf(),
        message_open_summary_path,
        plaintext_utf8,
        plaintext_len,
        group_id_ref,
        member_count,
        epoch_before,
        epoch_after,
        provider_storage_loaded: true,
        provider_storage_written: true,
        group_reloadable: true,
        message_opened: true,
    })
}
