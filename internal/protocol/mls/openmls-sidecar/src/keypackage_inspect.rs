use crate::labels::validate_device_label;
use crate::paths::{public_bundle_manifest_path, public_bundle_summary_path};
use crate::{IMPLEMENTATION, MODE, PROVIDER_NAME};
use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};
use tls_codec::Deserialize as TlsDeserializeTrait;

const PHASE_KEYPACKAGE_INSPECT: &str = "phase2d-keypackage-inspect-dev";

#[derive(Debug)]
struct InspectError {
    code: &'static str,
    message: String,
    exit_code: i32,
}

impl InspectError {
    fn new(code: &'static str, message: impl Into<String>, exit_code: i32) -> Self {
        Self {
            code,
            message: message.into(),
            exit_code,
        }
    }
}

pub fn handle_keypackage_inspect(args: &[String]) {
    let device_label = match option_value(args, "--device-label") {
        Some(value) => value,
        None => {
            print_failure(
                "missing_required_argument",
                "keypackage-inspect requires --device-label <label>",
            );
            process::exit(2);
        }
    };

    let keypackage_path = match option_value(args, "--keypackage") {
        Some(value) => value,
        None => {
            print_failure(
                "missing_required_argument",
                "keypackage-inspect requires --keypackage <path>",
            );
            process::exit(2);
        }
    };

    let generation_manifest_path = option_value(args, "--generation-manifest");

    if let Err(reason) = validate_device_label(device_label) {
        print_failure(
            "invalid_device_label",
            &format!("invalid device label {device_label:?}: {reason}"),
        );
        process::exit(2);
    }

    match inspect_keypackage(
        device_label,
        Path::new(keypackage_path),
        generation_manifest_path.map(|value| Path::new(value)),
    ) {
        Ok(data) => {
            let envelope = json!({
                "ok": true,
                "command": "keypackage-inspect",
                "provider": PROVIDER_NAME,
                "implementation": IMPLEMENTATION,
                "mode": MODE,
                "phase": PHASE_KEYPACKAGE_INSPECT,
                "data": data,
                "events": [],
                "warnings": [
                    "read-only dev KeyPackage inspection; local ownership evidence is not account, device, Relay Space, or human identity verification",
                    "OpenMLS validation and KeyPackage lifetime metadata are authoritative for this inspection surface",
                    "artifact SHA-256 is transport integrity metadata, not the KeyPackage lifecycle identity"
                ],
                "private_material_included": false
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&envelope)
                    .expect("KeyPackage inspection envelope should serialize")
            );
        }
        Err(err) => {
            print_failure(err.code, &err.message);
            process::exit(err.exit_code);
        }
    }
}

fn inspect_keypackage(
    device_label: &str,
    keypackage_path: &Path,
    generation_manifest_path: Option<&Path>,
) -> Result<Value, InspectError> {
    if !keypackage_path.is_file() {
        return Err(InspectError::new(
            "keypackage_artifact_missing",
            format!(
                "KeyPackage artifact is missing or not a regular file: {}",
                keypackage_path.display()
            ),
            3,
        ));
    }

    let artifact = fs::read(keypackage_path).map_err(|err| {
        InspectError::new(
            "keypackage_artifact_unreadable",
            format!(
                "read KeyPackage artifact {}: {err}",
                keypackage_path.display()
            ),
            3,
        )
    })?;

    let artifact_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&artifact)));
    let artifact_size = artifact.len();

    let mut slice = artifact.as_slice();
    let key_package_in = KeyPackageIn::tls_deserialize(&mut slice).map_err(|err| {
        InspectError::new(
            "keypackage_deserialize_failed",
            format!("deserialize KeyPackage artifact: {err:?}"),
            4,
        )
    })?;

    if !slice.is_empty() {
        return Err(InspectError::new(
            "keypackage_trailing_data",
            format!(
                "KeyPackage artifact contains {} trailing bytes",
                slice.len()
            ),
            4,
        ));
    }

    let crypto = RustCrypto::default();
    let key_package = key_package_in
        .validate(&crypto, ProtocolVersion::default())
        .map_err(|err| {
            InspectError::new(
                "keypackage_validation_failed",
                format!("OpenMLS KeyPackage validation failed: {err:?}"),
                4,
            )
        })?;

    let key_package_hash = key_package.hash_ref(&crypto).map_err(|err| {
        InspectError::new(
            "keypackage_ref_failed",
            format!("compute validated KeyPackage reference: {err:?}"),
            4,
        )
    })?;
    let key_package_ref = format!("sha256:{}", hex::encode(key_package_hash.as_slice()));

    let lifetime = key_package.life_time();
    let not_before = lifetime.not_before();
    let not_after = lifetime.not_after();
    let inspected_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| {
            InspectError::new(
                "system_time_invalid",
                format!("read inspection time: {err}"),
                4,
            )
        })?
        .as_secs();
    let valid_at_inspection_time = classify_lifetime(inspected_at, not_before, not_after)?;

    let (owner_match, owner_evidence, owner_manifest_path) = if let Some(generation_manifest_path) =
        generation_manifest_path
    {
        let generation_manifest =
            read_json(generation_manifest_path, "keypackage_generation_manifest")?;
        let manifest_device = required_string(
            &generation_manifest,
            "device_label",
            "keypackage_generation_manifest",
        )?;
        let manifest_ref = required_string(
            &generation_manifest,
            "key_package_ref",
            "keypackage_generation_manifest",
        )?;
        let manifest_sha = required_string(
            &generation_manifest,
            "artifact_sha256",
            "keypackage_generation_manifest",
        )?;
        let manifest_size = required_u64(
            &generation_manifest,
            "artifact_size_bytes",
            "keypackage_generation_manifest",
        )?;
        let manifest_not_before = required_u64(
            &generation_manifest,
            "lifetime_not_before_unix",
            "keypackage_generation_manifest",
        )?;
        let manifest_not_after = required_u64(
            &generation_manifest,
            "lifetime_not_after_unix",
            "keypackage_generation_manifest",
        )?;
        (
            manifest_device == device_label
                && manifest_ref == key_package_ref
                && manifest_sha == artifact_sha256
                && manifest_size == artifact_size as u64
                && manifest_not_before == not_before
                && manifest_not_after == not_after,
            "local-sidecar-keypackage-generation-manifest",
            Some(generation_manifest_path.to_string_lossy().to_string()),
        )
    } else {
        let summary_path = public_bundle_summary_path(device_label);
        let manifest_path = public_bundle_manifest_path(device_label);
        let summary = read_json(&summary_path, "public_bundle_summary")?;
        let manifest = read_json(&manifest_path, "public_bundle_manifest")?;

        let summary_device = required_string(&summary, "device_label", "public_bundle_summary")?;
        let manifest_device = required_string(&manifest, "device_label", "public_bundle_manifest")?;
        let summary_ref = required_string(&summary, "key_package_ref", "public_bundle_summary")?;
        let manifest_ref = required_string(&manifest, "key_package_ref", "public_bundle_manifest")?;
        let summary_sha = required_string(
            &summary,
            "key_package_artifact_sha256",
            "public_bundle_summary",
        )?;
        let manifest_sha = required_string(
            &manifest,
            "key_package_artifact_sha256",
            "public_bundle_manifest",
        )?;
        let summary_size = required_u64(
            &summary,
            "key_package_artifact_size_bytes",
            "public_bundle_summary",
        )?;
        let manifest_size = required_u64(
            &manifest,
            "key_package_artifact_size_bytes",
            "public_bundle_manifest",
        )?;
        (
            summary_device == device_label
                && manifest_device == device_label
                && summary_ref == key_package_ref
                && manifest_ref == key_package_ref
                && summary_sha == artifact_sha256
                && manifest_sha == artifact_sha256
                && summary_size == artifact_size as u64
                && manifest_size == artifact_size as u64,
            "local-sidecar-public-bundle-summary-and-manifest",
            None,
        )
    };

    if !owner_match {
        return Err(InspectError::new(
            "keypackage_owner_mismatch",
            format!(
                "KeyPackage artifact does not match local ownership metadata for device label {device_label}"
            ),
            5,
        ));
    }

    Ok(json!({
        "device_label": device_label,
        "keypackage_path": keypackage_path.to_string_lossy(),
        "key_package_ref": key_package_ref,
        "key_package_artifact_sha256": artifact_sha256,
        "key_package_artifact_size_bytes": artifact_size,
        "lifetime_not_before_unix": not_before,
        "lifetime_not_after_unix": not_after,
        "inspected_at_unix": inspected_at,
        "valid_at_inspection_time": valid_at_inspection_time,
        "openmls_validation_passed": true,
        "owner_match": true,
        "owner_evidence": owner_evidence,
        "generation_manifest_path": owner_manifest_path,
        "identity_binding": "local-sidecar-device-label-only",
        "local_state_mutated": false,
        "private_material_included": false
    }))
}

fn classify_lifetime(
    inspected_at: u64,
    not_before: u64,
    not_after: u64,
) -> Result<bool, InspectError> {
    if not_after <= not_before {
        return Err(InspectError::new(
            "keypackage_lifetime_invalid",
            format!(
                "KeyPackage lifetime is invalid: not_before={not_before} not_after={not_after}"
            ),
            6,
        ));
    }
    if inspected_at < not_before {
        return Err(InspectError::new(
            "keypackage_not_yet_valid",
            format!(
                "KeyPackage is not yet valid: inspected_at={inspected_at} not_before={not_before}"
            ),
            6,
        ));
    }
    if inspected_at >= not_after {
        return Err(InspectError::new(
            "keypackage_expired",
            format!("KeyPackage is expired: inspected_at={inspected_at} not_after={not_after}"),
            6,
        ));
    }
    Ok(true)
}

fn option_value<'a>(args: &'a [String], option: &str) -> Option<&'a str> {
    let mut index = 0;
    while index < args.len() {
        if args[index] == option {
            return args.get(index + 1).map(String::as_str);
        }
        index += 1;
    }
    None
}

fn read_json(path: &Path, label: &str) -> Result<Value, InspectError> {
    let bytes = fs::read(path).map_err(|err| {
        InspectError::new(
            "keypackage_owner_metadata_missing",
            format!("read {label} {}: {err}", path.display()),
            5,
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        InspectError::new(
            "keypackage_owner_metadata_invalid",
            format!("parse {label} {}: {err}", path.display()),
            5,
        )
    })
}

fn required_string(value: &Value, field: &str, label: &str) -> Result<String, InspectError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            InspectError::new(
                "keypackage_owner_metadata_invalid",
                format!("{label} field {field:?} is missing or not a string"),
                5,
            )
        })
}

fn required_u64(value: &Value, field: &str, label: &str) -> Result<u64, InspectError> {
    value.get(field).and_then(Value::as_u64).ok_or_else(|| {
        InspectError::new(
            "keypackage_owner_metadata_invalid",
            format!("{label} field {field:?} is missing or not an unsigned integer"),
            5,
        )
    })
}

fn print_failure(code: &str, message: &str) {
    let envelope = json!({
        "ok": false,
        "command": "keypackage-inspect",
        "provider": PROVIDER_NAME,
        "implementation": IMPLEMENTATION,
        "mode": MODE,
        "phase": PHASE_KEYPACKAGE_INSPECT,
        "error": {
            "code": code,
            "message": message,
            "provider_event": "provider.keypackage.inspect_refused",
            "severity": "warning",
            "trust_relevant": false
        },
        "events": [{
            "event": "provider.keypackage.inspect_refused",
            "severity": "warning",
            "trust_relevant": false
        }],
        "warnings": [],
        "private_material_included": false
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&envelope)
            .expect("KeyPackage inspection failure envelope should serialize")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_value_finds_explicit_arguments() {
        let args = vec![
            "--device-label".to_string(),
            "alice".to_string(),
            "--keypackage".to_string(),
            "alice.bin".to_string(),
        ];
        assert_eq!(option_value(&args, "--device-label"), Some("alice"));
        assert_eq!(option_value(&args, "--keypackage"), Some("alice.bin"));
        assert_eq!(option_value(&args, "--missing"), None);
    }

    #[test]
    fn lifetime_classifier_is_strict() {
        assert!(classify_lifetime(15, 10, 20).unwrap());
        assert_eq!(
            classify_lifetime(9, 10, 20).unwrap_err().code,
            "keypackage_not_yet_valid"
        );
        assert_eq!(
            classify_lifetime(20, 10, 20).unwrap_err().code,
            "keypackage_expired"
        );
        assert_eq!(
            classify_lifetime(10, 20, 20).unwrap_err().code,
            "keypackage_lifetime_invalid"
        );
    }

    #[test]
    fn required_metadata_helpers_are_strict() {
        let value = json!({
            "device_label": "alice",
            "key_package_artifact_size_bytes": 42
        });
        assert_eq!(
            required_string(&value, "device_label", "test").unwrap(),
            "alice"
        );
        assert_eq!(
            required_u64(&value, "key_package_artifact_size_bytes", "test").unwrap(),
            42
        );
        assert!(required_string(&value, "missing", "test").is_err());
        assert!(required_u64(&value, "device_label", "test").is_err());
    }
}
