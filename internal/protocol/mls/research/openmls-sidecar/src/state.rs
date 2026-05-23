use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

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
