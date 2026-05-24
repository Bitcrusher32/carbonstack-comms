use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use tls_codec::Serialize as TlsSerializeTrait;

pub const STATE_ROOT: &str = ".carbonstack-openmls-sidecar-state";
pub const DEV_SCOPE: &str = "dev";
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
pub fn conversation_state_dir(conversation_label: &str) -> PathBuf {
    Path::new(STATE_ROOT)
        .join(DEV_SCOPE)
        .join("conversations")
        .join(conversation_label)
}

pub fn conversation_summary_path(conversation_label: &str) -> PathBuf {
    conversation_state_dir(conversation_label).join("conversation-summary.json")
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

pub fn public_bundle_summary_path(device_label: &str) -> PathBuf {
    device_state_dir(device_label).join("public-bundle-summary.json")
}

pub fn public_bundle_keypackage_artifact_path(device_label: &str) -> PathBuf {
    device_state_dir(device_label).join("public-bundle.keypackage.bin")
}

pub fn public_bundle_manifest_path(device_label: &str) -> PathBuf {
    device_state_dir(device_label).join("public-bundle-manifest.json")
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

    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();

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
                provider_storage_written: false,
                private_material_included: false,
                warning: "dev-only serialized public KeyPackage artifact; not final CarbonStack onboarding material",
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
            provider_storage_written: false,
            private_material_included: false,
            warning: if write_artifact {
                "dev-only public bundle summary with serialized public KeyPackage artifact; not final CarbonStack onboarding material"
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
        provider_storage_written: false,
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
    private_material_included: bool,
    warning: &'a str,
}

pub fn create_dev_conversation(
    device_label: &str,
    conversation_label: &str,
) -> io::Result<ConversationCreateResult> {
    let status = load_dev_identity_status(device_label)?;

    let conversation_state_dir = conversation_state_dir(conversation_label);
    let conversation_summary_path = conversation_summary_path(conversation_label);

    if conversation_summary_path.exists() {
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

    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();

    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();

    let group_id_bytes = format!("carbonstack-openmls-dev-conversation:{conversation_label}");
    let group_id = GroupId::from_slice(group_id_bytes.as_bytes());

    let group = MlsGroup::new_with_group_id(
        &provider,
        &signer,
        &create_config,
        group_id,
        credential_with_key,
    )
    .map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("conversation group create failed: {err:?}"),
        )
    })?;

    let group_id_digest = Sha256::digest(group_id_bytes.as_bytes());
    let group_id_ref = format!("sha256:{}", hex::encode(group_id_digest));
    let epoch = format!("{:?}", group.epoch());
    let member_count = group.members().count();

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
            provider_storage_written: false,
            group_reloadable: false,
            private_material_included: false,
            warning: "dev-only OpenMLS conversation summary; group is not reloadable across sidecar process invocations yet; not production messaging or secure vault storage",
        },
    )?;

    Ok(ConversationCreateResult {
        device_label: device_label.to_string(),
        conversation_label: conversation_label.to_string(),
        conversation_state_dir,
        conversation_summary_path,
        group_id_ref,
        group_id_len: group_id_bytes.as_bytes().len(),
        member_count,
        epoch,
        provider_storage_written: false,
        group_reloadable: false,
    })
}
