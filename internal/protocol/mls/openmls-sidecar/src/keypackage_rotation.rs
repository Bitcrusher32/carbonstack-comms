use crate::labels::validate_device_label;
use crate::paths::{
    device_provider_storage_path, device_state_dir, public_bundle_keypackage_artifact_path,
    public_bundle_manifest_path, public_bundle_summary_path, signer_path,
};
use crate::provider::CarbonStackSidecarProvider;
use crate::state::{CIPHERSUITE_LABEL, load_dev_identity_status};
use crate::{IMPLEMENTATION, MODE, PROVIDER_NAME};
use openmls::key_packages::KeyPackageIn;
use openmls::prelude::*;
use openmls::versions::ProtocolVersion;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

const PHASE_GENERATE: &str = "phase2d-keypackage-generate-dev";
const PHASE_INVENTORY: &str = "phase2d-keypackage-inventory-dev";
const PHASE_RETIRE: &str = "phase2d-keypackage-retire-dev";
const INVENTORY_SCHEMA: &str = "carbonstack-keypackage-inventory/v1";
const MANIFEST_SCHEMA: &str = "carbonstack-keypackage-generation-manifest/v1";
const LEGACY_REQUEST_ID: &str = "legacy-public-bundle-import";
const LOCK_RETRIES: usize = 500;
const LOCK_DELAY_MS: u64 = 10;

#[derive(Debug)]
struct RotationError {
    code: &'static str,
    message: String,
    exit_code: i32,
}

impl RotationError {
    fn new(code: &'static str, message: impl Into<String>, exit_code: i32) -> Self {
        Self {
            code,
            message: message.into(),
            exit_code,
        }
    }

    fn io(code: &'static str, context: impl Into<String>, err: io::Error) -> Self {
        Self::new(code, format!("{}: {err}", context.into()), 4)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyPackageInventory {
    schema_version: String,
    device_label: String,
    next_sequence: u64,
    current_generation_id: Option<String>,
    generations: Vec<KeyPackageGenerationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyPackageGenerationRecord {
    generation_id: String,
    sequence: u64,
    request_id: String,
    key_package_ref: String,
    artifact_path: String,
    artifact_sha256: String,
    artifact_size_bytes: u64,
    manifest_path: String,
    lifetime_not_before_unix: u64,
    lifetime_not_after_unix: u64,
    created_at_unix: u64,
    status: String,
    retired_at_unix: Option<u64>,
    origin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyPackageGenerationManifest {
    schema_version: String,
    device_label: String,
    generation_id: String,
    sequence: u64,
    request_id: String,
    key_package_ref: String,
    artifact_file: String,
    artifact_sha256: String,
    artifact_size_bytes: u64,
    lifetime_not_before_unix: u64,
    lifetime_not_after_unix: u64,
    created_at_unix: u64,
    origin: String,
    ciphersuite: String,
    credential_type: String,
    private_material_included: bool,
}

#[derive(Debug)]
struct GeneratedMaterial {
    key_package_ref: String,
    artifact: Vec<u8>,
    artifact_sha256: String,
    lifetime_not_before_unix: u64,
    lifetime_not_after_unix: u64,
}

struct LifecycleLock {
    path: PathBuf,
}

impl Drop for LifecycleLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

pub fn handle_keypackage_generate(args: &[String]) {
    let device_label = match option_value(args, "--device-label") {
        Some(value) => value,
        None => {
            return exit_failure(
                "keypackage-generate",
                PHASE_GENERATE,
                RotationError::new(
                    "missing_required_argument",
                    "keypackage-generate requires --device-label <label>",
                    2,
                ),
            );
        }
    };
    let request_id = match option_value(args, "--request-id") {
        Some(value) => value,
        None => {
            return exit_failure(
                "keypackage-generate",
                PHASE_GENERATE,
                RotationError::new(
                    "missing_required_argument",
                    "keypackage-generate requires --request-id <safe-id>",
                    2,
                ),
            );
        }
    };

    if let Err(reason) = validate_device_label(device_label) {
        return exit_failure(
            "keypackage-generate",
            PHASE_GENERATE,
            RotationError::new(
                "invalid_device_label",
                format!("invalid device label {device_label:?}: {reason}"),
                2,
            ),
        );
    }
    if let Err(reason) = validate_device_label(request_id) {
        return exit_failure(
            "keypackage-generate",
            PHASE_GENERATE,
            RotationError::new(
                "invalid_request_id",
                format!("invalid request id {request_id:?}: {reason}"),
                2,
            ),
        );
    }

    match generate_keypackage(device_label, request_id) {
        Ok(value) => print_success("keypackage-generate", PHASE_GENERATE, value),
        Err(err) => exit_failure("keypackage-generate", PHASE_GENERATE, err),
    }
}

pub fn handle_keypackage_inventory(args: &[String]) {
    let device_label = match option_value(args, "--device-label") {
        Some(value) => value,
        None => {
            return exit_failure(
                "keypackage-inventory",
                PHASE_INVENTORY,
                RotationError::new(
                    "missing_required_argument",
                    "keypackage-inventory requires --device-label <label>",
                    2,
                ),
            );
        }
    };
    if let Err(reason) = validate_device_label(device_label) {
        return exit_failure(
            "keypackage-inventory",
            PHASE_INVENTORY,
            RotationError::new(
                "invalid_device_label",
                format!("invalid device label {device_label:?}: {reason}"),
                2,
            ),
        );
    }

    match inventory_value(device_label) {
        Ok(value) => print_success("keypackage-inventory", PHASE_INVENTORY, value),
        Err(err) => exit_failure("keypackage-inventory", PHASE_INVENTORY, err),
    }
}

pub fn handle_keypackage_retire(args: &[String]) {
    let device_label = match option_value(args, "--device-label") {
        Some(value) => value,
        None => {
            return exit_failure(
                "keypackage-retire",
                PHASE_RETIRE,
                RotationError::new(
                    "missing_required_argument",
                    "keypackage-retire requires --device-label <label>",
                    2,
                ),
            );
        }
    };
    let generation_id = match option_value(args, "--generation-id") {
        Some(value) => value,
        None => {
            return exit_failure(
                "keypackage-retire",
                PHASE_RETIRE,
                RotationError::new(
                    "missing_required_argument",
                    "keypackage-retire requires --generation-id <generation-id>",
                    2,
                ),
            );
        }
    };
    if let Err(reason) = validate_device_label(device_label) {
        return exit_failure(
            "keypackage-retire",
            PHASE_RETIRE,
            RotationError::new(
                "invalid_device_label",
                format!("invalid device label {device_label:?}: {reason}"),
                2,
            ),
        );
    }
    if !valid_generation_id(generation_id) {
        return exit_failure(
            "keypackage-retire",
            PHASE_RETIRE,
            RotationError::new(
                "invalid_generation_id",
                format!("invalid generation id {generation_id:?}"),
                2,
            ),
        );
    }

    match retire_keypackage(device_label, generation_id) {
        Ok(value) => print_success("keypackage-retire", PHASE_RETIRE, value),
        Err(err) => exit_failure("keypackage-retire", PHASE_RETIRE, err),
    }
}

fn generate_keypackage(device_label: &str, request_id: &str) -> Result<Value, RotationError> {
    load_dev_identity_status(device_label).map_err(|err| {
        RotationError::io("identity_unavailable", "load local sidecar identity", err)
    })?;

    let _lock = acquire_lock(device_label)?;
    fs::create_dir_all(generations_dir(device_label)).map_err(|err| {
        RotationError::io(
            "keypackage_state_write_failed",
            "create generation directory",
            err,
        )
    })?;

    let inventory_was_missing = !inventory_path(device_label).is_file();
    let mut inventory = load_or_initialize_inventory(device_label)?;

    if let Some(existing) = inventory
        .generations
        .iter()
        .find(|record| record.request_id == request_id)
        .cloned()
    {
        validate_record_files(device_label, &existing)?;
        let recovered_from_manifest = inventory_was_missing && existing.origin == "generated";
        return Ok(generation_value(
            &inventory,
            &existing,
            true,
            recovered_from_manifest,
        ));
    }

    if let Some(recovered) =
        recover_request_from_generation_dirs(device_label, request_id, &mut inventory)?
    {
        write_inventory_atomic(device_label, &inventory)?;
        return Ok(generation_value(&inventory, &recovered, true, true));
    }

    let sequence = next_available_sequence(device_label, &inventory)?;
    let generation_id = format!("kp-{sequence:06}");
    let created_at = unix_now()?;

    let provider_path = device_provider_storage_path(device_label);
    let mut provider = CarbonStackSidecarProvider::default();
    if provider_path.exists() {
        provider
            .load_storage_from_path(&provider_path)
            .map_err(|err| {
                RotationError::io(
                    "provider_storage_load_failed",
                    format!("load provider storage {}", provider_path.display()),
                    err,
                )
            })?;
    }

    let material = build_material(device_label, &provider)?;
    let suffix = ref_suffix(&material.key_package_ref)?;
    let final_dir = generations_dir(device_label).join(format!("{generation_id}-{suffix}"));
    if final_dir.exists() {
        return Err(RotationError::new(
            "generation_path_collision",
            format!("generation path already exists: {}", final_dir.display()),
            5,
        ));
    }

    let staging = staging_dir(device_label, request_id)?;
    fs::create_dir(&staging).map_err(|err| {
        RotationError::io(
            "generation_staging_failed",
            format!("create staging directory {}", staging.display()),
            err,
        )
    })?;

    let artifact_path = staging.join("keypackage.bin");
    let manifest_path = staging.join("manifest.json");
    let manifest = KeyPackageGenerationManifest {
        schema_version: MANIFEST_SCHEMA.to_string(),
        device_label: device_label.to_string(),
        generation_id: generation_id.clone(),
        sequence,
        request_id: request_id.to_string(),
        key_package_ref: material.key_package_ref.clone(),
        artifact_file: "keypackage.bin".to_string(),
        artifact_sha256: material.artifact_sha256.clone(),
        artifact_size_bytes: material.artifact.len() as u64,
        lifetime_not_before_unix: material.lifetime_not_before_unix,
        lifetime_not_after_unix: material.lifetime_not_after_unix,
        created_at_unix: created_at,
        origin: "generated".to_string(),
        ciphersuite: CIPHERSUITE_LABEL.to_string(),
        credential_type: "BasicCredential".to_string(),
        private_material_included: false,
    };

    let generation_result = (|| -> Result<(), RotationError> {
        write_bytes_synced(&artifact_path, &material.artifact)?;
        write_json_synced(&manifest_path, &manifest)?;
        save_provider_atomic(&provider, &provider_path)?;
        fs::rename(&staging, &final_dir).map_err(|err| {
            RotationError::io(
                "generation_publish_failed",
                format!(
                    "publish generation {} -> {}",
                    staging.display(),
                    final_dir.display()
                ),
                err,
            )
        })?;
        Ok(())
    })();

    if generation_result.is_err() && staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    generation_result?;

    let final_artifact = final_dir.join("keypackage.bin");
    let final_manifest = final_dir.join("manifest.json");
    let record = KeyPackageGenerationRecord {
        generation_id: generation_id.clone(),
        sequence,
        request_id: request_id.to_string(),
        key_package_ref: material.key_package_ref,
        artifact_path: path_string(&final_artifact),
        artifact_sha256: material.artifact_sha256,
        artifact_size_bytes: material.artifact.len() as u64,
        manifest_path: path_string(&final_manifest),
        lifetime_not_before_unix: material.lifetime_not_before_unix,
        lifetime_not_after_unix: material.lifetime_not_after_unix,
        created_at_unix: created_at,
        status: "active".to_string(),
        retired_at_unix: None,
        origin: "generated".to_string(),
    };

    inventory.next_sequence = sequence + 1;
    inventory.current_generation_id = Some(generation_id);
    inventory.generations.push(record.clone());
    inventory.generations.sort_by_key(|item| item.sequence);
    write_inventory_atomic(device_label, &inventory)?;

    Ok(generation_value(&inventory, &record, false, false))
}

fn inventory_value(device_label: &str) -> Result<Value, RotationError> {
    load_dev_identity_status(device_label).map_err(|err| {
        RotationError::io("identity_unavailable", "load local sidecar identity", err)
    })?;
    let inventory = load_inventory(device_label)?.ok_or_else(|| {
        RotationError::new(
            "keypackage_inventory_missing",
            "KeyPackage inventory does not exist; run keypackage-generate first",
            3,
        )
    })?;
    validate_inventory(device_label, &inventory)?;
    let active_count = inventory
        .generations
        .iter()
        .filter(|record| record.status == "active")
        .count();
    let retired_count = inventory.generations.len() - active_count;
    Ok(json!({
        "schema_version": inventory.schema_version,
        "device_label": inventory.device_label,
        "next_sequence": inventory.next_sequence,
        "current_generation_id": inventory.current_generation_id,
        "generation_count": inventory.generations.len(),
        "active_count": active_count,
        "retired_count": retired_count,
        "generations": inventory.generations,
        "local_state_mutated": false,
        "private_material_included": false
    }))
}

fn retire_keypackage(device_label: &str, generation_id: &str) -> Result<Value, RotationError> {
    let _lock = acquire_lock(device_label)?;
    let mut inventory = load_inventory(device_label)?.ok_or_else(|| {
        RotationError::new(
            "keypackage_inventory_missing",
            "KeyPackage inventory does not exist",
            3,
        )
    })?;
    validate_inventory(device_label, &inventory)?;

    if inventory.current_generation_id.as_deref() == Some(generation_id) {
        return Err(RotationError::new(
            "current_generation_retirement_refused",
            format!("current generation cannot be retired: {generation_id}"),
            5,
        ));
    }

    let index = inventory
        .generations
        .iter()
        .position(|record| record.generation_id == generation_id)
        .ok_or_else(|| {
            RotationError::new(
                "generation_not_found",
                format!("unknown generation: {generation_id}"),
                3,
            )
        })?;

    if inventory.generations[index].status == "retired" {
        return Ok(json!({
            "device_label": device_label,
            "generation_id": generation_id,
            "status": "retired",
            "retired_at_unix": inventory.generations[index].retired_at_unix,
            "idempotent_replay": true,
            "artifact_retained": true,
            "provider_storage_retained": true,
            "private_material_included": false
        }));
    }

    validate_record_files(device_label, &inventory.generations[index])?;
    let retired_at = unix_now()?;
    inventory.generations[index].status = "retired".to_string();
    inventory.generations[index].retired_at_unix = Some(retired_at);
    write_inventory_atomic(device_label, &inventory)?;

    Ok(json!({
        "device_label": device_label,
        "generation_id": generation_id,
        "status": "retired",
        "retired_at_unix": retired_at,
        "idempotent_replay": false,
        "artifact_retained": true,
        "provider_storage_retained": true,
        "private_material_included": false
    }))
}

fn load_or_initialize_inventory(device_label: &str) -> Result<KeyPackageInventory, RotationError> {
    if let Some(inventory) = load_inventory(device_label)? {
        validate_inventory(device_label, &inventory)?;
        return Ok(inventory);
    }

    let provider_exists = device_provider_storage_path(device_label).exists();
    let legacy_artifact = public_bundle_keypackage_artifact_path(device_label);
    let legacy_summary = public_bundle_summary_path(device_label);
    let legacy_manifest = public_bundle_manifest_path(device_label);
    let legacy_count = [
        legacy_artifact.exists(),
        legacy_summary.exists(),
        legacy_manifest.exists(),
    ]
    .into_iter()
    .filter(|value| *value)
    .count();
    let mut generation_records = scan_generation_records(device_label)?;

    if !provider_exists && !generation_records.is_empty() {
        return Err(RotationError::new(
            "incomplete_keypackage_state",
            "immutable KeyPackage generations exist without provider storage",
            5,
        ));
    }

    if provider_exists && legacy_count == 0 && !generation_records.is_empty() {
        if generation_records.len() != 1 {
            return Err(RotationError::new(
                "keypackage_inventory_recovery_ambiguous",
                format!(
                    "inventory is missing with {} immutable generations and no legacy authority",
                    generation_records.len()
                ),
                5,
            ));
        }
        let record = generation_records.remove(0);
        if record.sequence != 1
            || record.generation_id != "kp-000001"
            || record.origin != "generated"
        {
            return Err(RotationError::new(
                "keypackage_inventory_recovery_ambiguous",
                "inventory-free provider state can recover only one first generated KeyPackage",
                5,
            ));
        }
        let inventory = KeyPackageInventory {
            schema_version: INVENTORY_SCHEMA.to_string(),
            device_label: device_label.to_string(),
            next_sequence: 2,
            current_generation_id: Some(record.generation_id.clone()),
            generations: vec![record],
        };
        write_inventory_atomic(device_label, &inventory)?;
        return Ok(inventory);
    }

    if provider_exists && legacy_count != 3 {
        return Err(RotationError::new(
            "incomplete_legacy_keypackage_state",
            format!(
                "provider storage exists but fixed legacy KeyPackage state is incomplete: artifact={} summary={} manifest={}",
                legacy_artifact.exists(),
                legacy_summary.exists(),
                legacy_manifest.exists()
            ),
            5,
        ));
    }
    if !provider_exists && legacy_count != 0 {
        return Err(RotationError::new(
            "incomplete_legacy_keypackage_state",
            "fixed legacy KeyPackage files exist without provider storage",
            5,
        ));
    }

    let mut inventory = KeyPackageInventory {
        schema_version: INVENTORY_SCHEMA.to_string(),
        device_label: device_label.to_string(),
        next_sequence: 1,
        current_generation_id: None,
        generations: Vec::new(),
    };

    if provider_exists {
        let legacy_record = adopt_legacy(device_label)?;
        inventory.next_sequence = 2;
        inventory.current_generation_id = Some(legacy_record.generation_id.clone());
        inventory.generations.push(legacy_record);
        write_inventory_atomic(device_label, &inventory)?;
    }

    Ok(inventory)
}

fn adopt_legacy(device_label: &str) -> Result<KeyPackageGenerationRecord, RotationError> {
    let artifact_path = public_bundle_keypackage_artifact_path(device_label);
    let summary_path = public_bundle_summary_path(device_label);
    let manifest_path = public_bundle_manifest_path(device_label);

    let artifact = fs::read(&artifact_path).map_err(|err| {
        RotationError::io(
            "legacy_artifact_read_failed",
            "read legacy KeyPackage artifact",
            err,
        )
    })?;
    let validated = validate_serialized_keypackage(&artifact)?;
    let summary: Value = read_json(&summary_path, "legacy public bundle summary")?;
    let manifest_value: Value = read_json(&manifest_path, "legacy public bundle manifest")?;
    let artifact_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&artifact)));

    for (label, value) in [("summary", &summary), ("manifest", &manifest_value)] {
        require_json_string(value, "device_label", label, device_label)?;
        require_json_string(value, "key_package_ref", label, &validated.key_package_ref)?;
        require_json_string(
            value,
            "key_package_artifact_sha256",
            label,
            &artifact_sha256,
        )?;
        require_json_u64(
            value,
            "key_package_artifact_size_bytes",
            label,
            artifact.len() as u64,
        )?;
    }

    let generation_id = "kp-000001".to_string();
    let suffix = ref_suffix(&validated.key_package_ref)?;
    let final_dir = generations_dir(device_label).join(format!("{generation_id}-{suffix}"));
    let created_at = unix_now()?;

    if final_dir.exists() {
        let existing_manifest_path = final_dir.join("manifest.json");
        let existing_manifest: KeyPackageGenerationManifest =
            read_json(&existing_manifest_path, "legacy generation manifest")?;
        if existing_manifest.request_id != LEGACY_REQUEST_ID
            || existing_manifest.origin != "legacy_import"
        {
            return Err(RotationError::new(
                "legacy_import_conflict",
                format!("legacy generation path conflicts: {}", final_dir.display()),
                5,
            ));
        }
        let existing = record_from_manifest(&existing_manifest_path, &existing_manifest)?;
        validate_record_files(device_label, &existing)?;
        return Ok(existing);
    } else {
        let staging = staging_dir(device_label, LEGACY_REQUEST_ID)?;
        fs::create_dir(&staging).map_err(|err| {
            RotationError::io(
                "legacy_import_failed",
                "create legacy staging directory",
                err,
            )
        })?;
        let generation_manifest = KeyPackageGenerationManifest {
            schema_version: MANIFEST_SCHEMA.to_string(),
            device_label: device_label.to_string(),
            generation_id: generation_id.clone(),
            sequence: 1,
            request_id: LEGACY_REQUEST_ID.to_string(),
            key_package_ref: validated.key_package_ref.clone(),
            artifact_file: "keypackage.bin".to_string(),
            artifact_sha256: artifact_sha256.clone(),
            artifact_size_bytes: artifact.len() as u64,
            lifetime_not_before_unix: validated.lifetime_not_before_unix,
            lifetime_not_after_unix: validated.lifetime_not_after_unix,
            created_at_unix: created_at,
            origin: "legacy_import".to_string(),
            ciphersuite: CIPHERSUITE_LABEL.to_string(),
            credential_type: "BasicCredential".to_string(),
            private_material_included: false,
        };
        let import_result = (|| -> Result<(), RotationError> {
            write_bytes_synced(&staging.join("keypackage.bin"), &artifact)?;
            write_json_synced(&staging.join("manifest.json"), &generation_manifest)?;
            fs::rename(&staging, &final_dir).map_err(|err| {
                RotationError::io("legacy_import_failed", "publish legacy generation", err)
            })?;
            Ok(())
        })();
        if import_result.is_err() && staging.exists() {
            let _ = fs::remove_dir_all(&staging);
        }
        import_result?;
    }

    let final_artifact = final_dir.join("keypackage.bin");
    let final_manifest = final_dir.join("manifest.json");
    let record = KeyPackageGenerationRecord {
        generation_id,
        sequence: 1,
        request_id: LEGACY_REQUEST_ID.to_string(),
        key_package_ref: validated.key_package_ref,
        artifact_path: path_string(&final_artifact),
        artifact_sha256,
        artifact_size_bytes: artifact.len() as u64,
        manifest_path: path_string(&final_manifest),
        lifetime_not_before_unix: validated.lifetime_not_before_unix,
        lifetime_not_after_unix: validated.lifetime_not_after_unix,
        created_at_unix: created_at,
        status: "active".to_string(),
        retired_at_unix: None,
        origin: "legacy_import".to_string(),
    };
    validate_record_files(device_label, &record)?;
    Ok(record)
}

fn scan_generation_records(
    device_label: &str,
) -> Result<Vec<KeyPackageGenerationRecord>, RotationError> {
    let root = generations_dir(device_label);
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut records = Vec::new();
    for entry in fs::read_dir(&root).map_err(|err| {
        RotationError::io("generation_scan_failed", "scan generation directories", err)
    })? {
        let entry = entry.map_err(|err| {
            RotationError::io(
                "generation_scan_failed",
                "read generation directory entry",
                err,
            )
        })?;
        if !entry
            .file_type()
            .map_err(|err| {
                RotationError::io("generation_scan_failed", "read generation entry type", err)
            })?
            .is_dir()
        {
            return Err(RotationError::new(
                "generation_state_invalid",
                format!(
                    "unexpected non-directory in generations root: {}",
                    entry.path().display()
                ),
                5,
            ));
        }
        let manifest_path = entry.path().join("manifest.json");
        if !manifest_path.is_file() {
            return Err(RotationError::new(
                "generation_manifest_missing",
                format!(
                    "immutable generation lacks manifest: {}",
                    entry.path().display()
                ),
                5,
            ));
        }
        let manifest: KeyPackageGenerationManifest =
            read_json(&manifest_path, "generation manifest")?;
        let record = record_from_manifest(&manifest_path, &manifest)?;
        validate_record_files(device_label, &record)?;
        records.push(record);
    }
    records.sort_by_key(|record| record.sequence);

    let mut generation_ids = std::collections::BTreeSet::new();
    let mut sequences = std::collections::BTreeSet::new();
    let mut request_ids = std::collections::BTreeSet::new();
    for record in &records {
        if !generation_ids.insert(record.generation_id.clone())
            || !sequences.insert(record.sequence)
            || !request_ids.insert(record.request_id.clone())
        {
            return Err(RotationError::new(
                "generation_state_invalid",
                "immutable generation directories contain duplicate lifecycle identities",
                5,
            ));
        }
    }
    Ok(records)
}

fn recover_request_from_generation_dirs(
    device_label: &str,
    request_id: &str,
    inventory: &mut KeyPackageInventory,
) -> Result<Option<KeyPackageGenerationRecord>, RotationError> {
    for record in scan_generation_records(device_label)? {
        if record.request_id != request_id {
            continue;
        }
        if inventory
            .generations
            .iter()
            .any(|existing| existing.request_id == request_id)
        {
            return Ok(None);
        }
        if record.sequence < inventory.next_sequence {
            return Err(RotationError::new(
                "generation_recovery_conflict",
                format!(
                    "unindexed request {} has stale sequence {} below next sequence {}",
                    request_id, record.sequence, inventory.next_sequence
                ),
                5,
            ));
        }
        inventory.next_sequence = inventory.next_sequence.max(record.sequence + 1);
        inventory.current_generation_id = Some(record.generation_id.clone());
        inventory.generations.push(record.clone());
        inventory.generations.sort_by_key(|item| item.sequence);
        return Ok(Some(record));
    }
    Ok(None)
}

fn record_from_manifest(
    manifest_path: &Path,
    manifest: &KeyPackageGenerationManifest,
) -> Result<KeyPackageGenerationRecord, RotationError> {
    let parent = manifest_path.parent().ok_or_else(|| {
        RotationError::new(
            "generation_manifest_invalid",
            "generation manifest has no parent",
            5,
        )
    })?;
    Ok(KeyPackageGenerationRecord {
        generation_id: manifest.generation_id.clone(),
        sequence: manifest.sequence,
        request_id: manifest.request_id.clone(),
        key_package_ref: manifest.key_package_ref.clone(),
        artifact_path: path_string(&parent.join(&manifest.artifact_file)),
        artifact_sha256: manifest.artifact_sha256.clone(),
        artifact_size_bytes: manifest.artifact_size_bytes,
        manifest_path: path_string(manifest_path),
        lifetime_not_before_unix: manifest.lifetime_not_before_unix,
        lifetime_not_after_unix: manifest.lifetime_not_after_unix,
        created_at_unix: manifest.created_at_unix,
        status: "active".to_string(),
        retired_at_unix: None,
        origin: manifest.origin.clone(),
    })
}

fn build_material(
    device_label: &str,
    provider: &CarbonStackSidecarProvider,
) -> Result<GeneratedMaterial, RotationError> {
    let signer_path = signer_path(device_label);
    let signer: SignatureKeyPair = read_json(&signer_path, "local signer")?;
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let credential = BasicCredential::new(device_label.as_bytes().to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    let bundle = KeyPackage::builder()
        .build(ciphersuite, provider, &signer, credential_with_key)
        .map_err(|err| {
            RotationError::new(
                "keypackage_build_failed",
                format!("OpenMLS KeyPackage build failed: {err:?}"),
                4,
            )
        })?;
    let key_package = bundle.key_package().clone();
    let hash = key_package.hash_ref(provider.crypto()).map_err(|err| {
        RotationError::new(
            "keypackage_ref_failed",
            format!("compute KeyPackage reference: {err:?}"),
            4,
        )
    })?;
    let key_package_ref = format!("sha256:{}", hex::encode(hash.as_slice()));
    let artifact = key_package.tls_serialize_detached().map_err(|err| {
        RotationError::new(
            "keypackage_serialize_failed",
            format!("serialize KeyPackage: {err:?}"),
            4,
        )
    })?;
    let artifact_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&artifact)));
    let lifetime = key_package.life_time();
    Ok(GeneratedMaterial {
        key_package_ref,
        artifact,
        artifact_sha256,
        lifetime_not_before_unix: lifetime.not_before(),
        lifetime_not_after_unix: lifetime.not_after(),
    })
}

fn validate_serialized_keypackage(artifact: &[u8]) -> Result<GeneratedMaterial, RotationError> {
    let mut slice = artifact;
    let input = KeyPackageIn::tls_deserialize(&mut slice).map_err(|err| {
        RotationError::new(
            "keypackage_deserialize_failed",
            format!("deserialize KeyPackage: {err:?}"),
            4,
        )
    })?;
    if !slice.is_empty() {
        return Err(RotationError::new(
            "keypackage_trailing_data",
            format!("KeyPackage contains {} trailing bytes", slice.len()),
            4,
        ));
    }
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let key_package = input
        .validate(&crypto, ProtocolVersion::default())
        .map_err(|err| {
            RotationError::new(
                "keypackage_validation_failed",
                format!("validate KeyPackage: {err:?}"),
                4,
            )
        })?;
    let hash = key_package.hash_ref(&crypto).map_err(|err| {
        RotationError::new(
            "keypackage_ref_failed",
            format!("compute KeyPackage reference: {err:?}"),
            4,
        )
    })?;
    let lifetime = key_package.life_time();
    Ok(GeneratedMaterial {
        key_package_ref: format!("sha256:{}", hex::encode(hash.as_slice())),
        artifact: artifact.to_vec(),
        artifact_sha256: format!("sha256:{}", hex::encode(Sha256::digest(artifact))),
        lifetime_not_before_unix: lifetime.not_before(),
        lifetime_not_after_unix: lifetime.not_after(),
    })
}

fn load_inventory(device_label: &str) -> Result<Option<KeyPackageInventory>, RotationError> {
    let path = inventory_path(device_label);
    if !path.exists() {
        return Ok(None);
    }
    let inventory: KeyPackageInventory = read_json(&path, "KeyPackage inventory")?;
    Ok(Some(inventory))
}

fn validate_inventory(
    device_label: &str,
    inventory: &KeyPackageInventory,
) -> Result<(), RotationError> {
    if inventory.schema_version != INVENTORY_SCHEMA {
        return Err(RotationError::new(
            "keypackage_inventory_invalid",
            format!("unsupported inventory schema {}", inventory.schema_version),
            5,
        ));
    }
    if inventory.device_label != device_label {
        return Err(RotationError::new(
            "keypackage_inventory_invalid",
            "inventory device label mismatch",
            5,
        ));
    }
    let mut seen_generation = std::collections::BTreeSet::new();
    let mut seen_request = std::collections::BTreeSet::new();
    for record in &inventory.generations {
        if !seen_generation.insert(record.generation_id.clone()) {
            return Err(RotationError::new(
                "keypackage_inventory_invalid",
                format!("duplicate generation id {}", record.generation_id),
                5,
            ));
        }
        if !seen_request.insert(record.request_id.clone()) {
            return Err(RotationError::new(
                "keypackage_inventory_invalid",
                format!("duplicate request id {}", record.request_id),
                5,
            ));
        }
        if record.status != "active" && record.status != "retired" {
            return Err(RotationError::new(
                "keypackage_inventory_invalid",
                format!("invalid generation status {}", record.status),
                5,
            ));
        }
        validate_record_files(device_label, record)?;
    }
    if let Some(current) = &inventory.current_generation_id {
        let current_record = inventory
            .generations
            .iter()
            .find(|record| &record.generation_id == current)
            .ok_or_else(|| {
                RotationError::new(
                    "keypackage_inventory_invalid",
                    "current generation does not exist",
                    5,
                )
            })?;
        if current_record.status != "active" {
            return Err(RotationError::new(
                "keypackage_inventory_invalid",
                "current generation is not active",
                5,
            ));
        }
    } else if !inventory.generations.is_empty() {
        return Err(RotationError::new(
            "keypackage_inventory_invalid",
            "non-empty inventory has no current generation",
            5,
        ));
    }
    Ok(())
}

fn validate_record_files(
    device_label: &str,
    record: &KeyPackageGenerationRecord,
) -> Result<(), RotationError> {
    let artifact_path = Path::new(&record.artifact_path);
    let manifest_path = Path::new(&record.manifest_path);
    if !artifact_path.is_file() || !manifest_path.is_file() {
        return Err(RotationError::new(
            "generation_artifact_missing",
            format!(
                "generation {} artifact or manifest is missing",
                record.generation_id
            ),
            5,
        ));
    }
    let manifest: KeyPackageGenerationManifest = read_json(manifest_path, "generation manifest")?;
    let expected_suffix = ref_suffix(&record.key_package_ref)?;
    let expected_dir =
        generations_dir(device_label).join(format!("{}-{}", record.generation_id, expected_suffix));
    let expected_artifact_path = expected_dir.join("keypackage.bin");
    let expected_manifest_path = expected_dir.join("manifest.json");
    if artifact_path != expected_artifact_path.as_path()
        || manifest_path != expected_manifest_path.as_path()
        || manifest.schema_version != MANIFEST_SCHEMA
        || manifest.device_label != device_label
        || manifest.generation_id != record.generation_id
        || manifest.sequence != record.sequence
        || manifest.request_id != record.request_id
        || manifest.key_package_ref != record.key_package_ref
        || manifest.artifact_file != "keypackage.bin"
        || manifest.artifact_sha256 != record.artifact_sha256
        || manifest.artifact_size_bytes != record.artifact_size_bytes
        || manifest.lifetime_not_before_unix != record.lifetime_not_before_unix
        || manifest.lifetime_not_after_unix != record.lifetime_not_after_unix
        || manifest.created_at_unix != record.created_at_unix
        || manifest.origin != record.origin
        || manifest.ciphersuite != CIPHERSUITE_LABEL
        || manifest.credential_type != "BasicCredential"
        || manifest.private_material_included
    {
        return Err(RotationError::new(
            "generation_manifest_mismatch",
            format!(
                "generation {} manifest does not match inventory",
                record.generation_id
            ),
            5,
        ));
    }
    let artifact = fs::read(artifact_path).map_err(|err| {
        RotationError::io(
            "generation_artifact_read_failed",
            "read generation artifact",
            err,
        )
    })?;
    if artifact.len() as u64 != record.artifact_size_bytes
        || format!("sha256:{}", hex::encode(Sha256::digest(&artifact))) != record.artifact_sha256
    {
        return Err(RotationError::new(
            "generation_artifact_mismatch",
            format!(
                "generation {} artifact integrity mismatch",
                record.generation_id
            ),
            5,
        ));
    }
    let validated = validate_serialized_keypackage(&artifact)?;
    if validated.key_package_ref != record.key_package_ref
        || validated.lifetime_not_before_unix != record.lifetime_not_before_unix
        || validated.lifetime_not_after_unix != record.lifetime_not_after_unix
    {
        return Err(RotationError::new(
            "generation_artifact_mismatch",
            format!(
                "generation {} OpenMLS metadata mismatch",
                record.generation_id
            ),
            5,
        ));
    }
    Ok(())
}

fn next_available_sequence(
    device_label: &str,
    inventory: &KeyPackageInventory,
) -> Result<u64, RotationError> {
    let mut maximum = inventory
        .generations
        .iter()
        .map(|record| record.sequence)
        .max()
        .unwrap_or(0);
    let root = generations_dir(device_label);
    if root.exists() {
        for entry in fs::read_dir(root).map_err(|err| {
            RotationError::io("generation_scan_failed", "scan generation directories", err)
        })? {
            let entry = entry.map_err(|err| {
                RotationError::io(
                    "generation_scan_failed",
                    "read generation directory entry",
                    err,
                )
            })?;
            if !entry
                .file_type()
                .map_err(|err| {
                    RotationError::io("generation_scan_failed", "read generation entry type", err)
                })?
                .is_dir()
            {
                continue;
            }
            let manifest_path = entry.path().join("manifest.json");
            if manifest_path.is_file() {
                let manifest: KeyPackageGenerationManifest =
                    read_json(&manifest_path, "generation manifest")?;
                maximum = maximum.max(manifest.sequence);
            }
        }
    }
    Ok(inventory.next_sequence.max(maximum + 1))
}

fn generation_value(
    inventory: &KeyPackageInventory,
    record: &KeyPackageGenerationRecord,
    idempotent_replay: bool,
    recovered_from_manifest: bool,
) -> Value {
    json!({
        "device_label": &inventory.device_label,
        "generation_id": &record.generation_id,
        "sequence": record.sequence,
        "request_id": &record.request_id,
        "key_package_ref": &record.key_package_ref,
        "artifact_path": &record.artifact_path,
        "artifact_sha256": &record.artifact_sha256,
        "artifact_size_bytes": record.artifact_size_bytes,
        "manifest_path": &record.manifest_path,
        "lifetime_not_before_unix": record.lifetime_not_before_unix,
        "lifetime_not_after_unix": record.lifetime_not_after_unix,
        "status": &record.status,
        "origin": &record.origin,
        "current_generation_id": &inventory.current_generation_id,
        "generation_count": inventory.generations.len(),
        "idempotent_replay": idempotent_replay,
        "recovered_from_manifest": recovered_from_manifest,
        "provider_storage_persisted": true,
        "private_material_included": false
    })
}

fn acquire_lock(device_label: &str) -> Result<LifecycleLock, RotationError> {
    let path = lock_path(device_label);
    fs::create_dir_all(keypackages_root(device_label)).map_err(|err| {
        RotationError::io(
            "keypackage_state_write_failed",
            "create keypackages root",
            err,
        )
    })?;
    for _ in 0..LOCK_RETRIES {
        match fs::create_dir(&path) {
            Ok(()) => return Ok(LifecycleLock { path }),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                thread::sleep(Duration::from_millis(LOCK_DELAY_MS));
            }
            Err(err) => {
                return Err(RotationError::io(
                    "keypackage_lifecycle_lock_failed",
                    format!("acquire lifecycle lock {}", path.display()),
                    err,
                ));
            }
        }
    }
    Err(RotationError::new(
        "keypackage_lifecycle_busy",
        format!("device KeyPackage lifecycle is busy: {}", path.display()),
        6,
    ))
}

fn save_provider_atomic(
    provider: &CarbonStackSidecarProvider,
    path: &Path,
) -> Result<(), RotationError> {
    let temp = temporary_sibling(path, "provider")?;
    provider.save_storage_to_path(&temp).map_err(|err| {
        RotationError::io(
            "provider_storage_write_failed",
            "write provider storage temp",
            err,
        )
    })?;
    fs::rename(&temp, path).map_err(|err| {
        let _ = fs::remove_file(&temp);
        RotationError::io(
            "provider_storage_write_failed",
            "replace provider storage",
            err,
        )
    })
}

fn write_inventory_atomic(
    device_label: &str,
    inventory: &KeyPackageInventory,
) -> Result<(), RotationError> {
    validate_inventory(device_label, inventory)?;
    let path = inventory_path(device_label);
    fs::create_dir_all(keypackages_root(device_label)).map_err(|err| {
        RotationError::io(
            "keypackage_inventory_write_failed",
            "create inventory directory",
            err,
        )
    })?;
    let temp = temporary_sibling(&path, "inventory")?;
    write_json_synced(&temp, inventory)?;
    fs::rename(&temp, &path).map_err(|err| {
        let _ = fs::remove_file(&temp);
        RotationError::io(
            "keypackage_inventory_write_failed",
            "replace inventory",
            err,
        )
    })
}

fn write_json_synced<T: Serialize>(path: &Path, value: &T) -> Result<(), RotationError> {
    let mut file = File::create(path).map_err(|err| {
        RotationError::io(
            "keypackage_state_write_failed",
            format!("create {}", path.display()),
            err,
        )
    })?;
    serde_json::to_writer_pretty(&mut file, value).map_err(|err| {
        RotationError::new(
            "keypackage_state_write_failed",
            format!("serialize {}: {err}", path.display()),
            4,
        )
    })?;
    file.write_all(b"\n").map_err(|err| {
        RotationError::io("keypackage_state_write_failed", "finalize JSON file", err)
    })?;
    file.sync_all()
        .map_err(|err| RotationError::io("keypackage_state_write_failed", "sync JSON file", err))
}

fn write_bytes_synced(path: &Path, bytes: &[u8]) -> Result<(), RotationError> {
    let mut file = File::create(path).map_err(|err| {
        RotationError::io(
            "keypackage_state_write_failed",
            format!("create {}", path.display()),
            err,
        )
    })?;
    file.write_all(bytes).map_err(|err| {
        RotationError::io(
            "keypackage_state_write_failed",
            "write KeyPackage artifact",
            err,
        )
    })?;
    file.sync_all().map_err(|err| {
        RotationError::io(
            "keypackage_state_write_failed",
            "sync KeyPackage artifact",
            err,
        )
    })
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T, RotationError> {
    let file = File::open(path).map_err(|err| {
        RotationError::io(
            "keypackage_state_read_failed",
            format!("read {label} {}", path.display()),
            err,
        )
    })?;
    serde_json::from_reader(file).map_err(|err| {
        RotationError::new(
            "keypackage_state_invalid",
            format!("parse {label} {}: {err}", path.display()),
            5,
        )
    })
}

fn require_json_string(
    value: &Value,
    field: &str,
    label: &str,
    expected: &str,
) -> Result<(), RotationError> {
    let actual = value.get(field).and_then(Value::as_str).ok_or_else(|| {
        RotationError::new(
            "incomplete_legacy_keypackage_state",
            format!("{label} field {field:?} is missing or invalid"),
            5,
        )
    })?;
    if actual != expected {
        return Err(RotationError::new(
            "incomplete_legacy_keypackage_state",
            format!("{label} field {field:?} mismatch"),
            5,
        ));
    }
    Ok(())
}

fn require_json_u64(
    value: &Value,
    field: &str,
    label: &str,
    expected: u64,
) -> Result<(), RotationError> {
    let actual = value.get(field).and_then(Value::as_u64).ok_or_else(|| {
        RotationError::new(
            "incomplete_legacy_keypackage_state",
            format!("{label} field {field:?} is missing or invalid"),
            5,
        )
    })?;
    if actual != expected {
        return Err(RotationError::new(
            "incomplete_legacy_keypackage_state",
            format!("{label} field {field:?} mismatch"),
            5,
        ));
    }
    Ok(())
}

fn option_value<'a>(args: &'a [String], option: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == option)
        .map(|pair| pair[1].as_str())
}

fn valid_generation_id(value: &str) -> bool {
    value.len() == 9
        && value.starts_with("kp-")
        && value[3..]
            .chars()
            .all(|character| character.is_ascii_digit())
}

fn ref_suffix(key_package_ref: &str) -> Result<String, RotationError> {
    let hex = key_package_ref.strip_prefix("sha256:").ok_or_else(|| {
        RotationError::new(
            "keypackage_ref_invalid",
            "KeyPackage ref lacks sha256 prefix",
            5,
        )
    })?;
    if hex.len() < 16 || !hex.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(RotationError::new(
            "keypackage_ref_invalid",
            "KeyPackage ref is not safe hexadecimal",
            5,
        ));
    }
    Ok(hex[..16].to_ascii_lowercase())
}

fn unix_now() -> Result<u64, RotationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| RotationError::new("system_time_invalid", err.to_string(), 4))
}

fn unique_token() -> Result<String, RotationError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| RotationError::new("system_time_invalid", err.to_string(), 4))?
        .as_nanos();
    Ok(format!("{}-{nanos}", process::id()))
}

fn keypackages_root(device_label: &str) -> PathBuf {
    device_state_dir(device_label).join("keypackages")
}

fn inventory_path(device_label: &str) -> PathBuf {
    keypackages_root(device_label).join("inventory.json")
}

fn generations_dir(device_label: &str) -> PathBuf {
    keypackages_root(device_label).join("generations")
}

fn lock_path(device_label: &str) -> PathBuf {
    keypackages_root(device_label).join(".lifecycle-lock")
}

fn staging_dir(device_label: &str, request_id: &str) -> Result<PathBuf, RotationError> {
    Ok(keypackages_root(device_label).join(format!(".staging-{}-{}", request_id, unique_token()?)))
}

fn temporary_sibling(path: &Path, label: &str) -> Result<PathBuf, RotationError> {
    let parent = path.parent().ok_or_else(|| {
        RotationError::new("keypackage_state_write_failed", "path has no parent", 4)
    })?;
    Ok(parent.join(format!(".{label}-{}.tmp", unique_token()?)))
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn print_success(command: &str, phase: &str, data: Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "command": command,
            "provider": PROVIDER_NAME,
            "implementation": IMPLEMENTATION,
            "mode": MODE,
            "phase": phase,
            "data": data,
            "events": [],
            "warnings": [
                "dev-local repeatable KeyPackage lifecycle; not Relay publication or production onboarding",
                "retirement is metadata-only and does not delete private provider state",
                "private material is persisted locally but never printed"
            ],
            "private_material_included": false
        }))
        .expect("KeyPackage lifecycle success envelope should serialize")
    );
}

fn exit_failure(command: &str, phase: &str, err: RotationError) {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": false,
            "command": command,
            "provider": PROVIDER_NAME,
            "implementation": IMPLEMENTATION,
            "mode": MODE,
            "phase": phase,
            "error": {
                "code": err.code,
                "message": err.message,
                "provider_event": "provider.keypackage.lifecycle_refused",
                "severity": "warning",
                "trust_relevant": false
            },
            "events": [{
                "event": "provider.keypackage.lifecycle_refused",
                "severity": "warning",
                "trust_relevant": false
            }],
            "warnings": [],
            "private_material_included": false
        }))
        .expect("KeyPackage lifecycle failure envelope should serialize")
    );
    process::exit(err.exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_ids_are_strict() {
        assert!(valid_generation_id("kp-000001"));
        assert!(!valid_generation_id("kp-1"));
        assert!(!valid_generation_id("xx-000001"));
    }

    #[test]
    fn ref_suffix_is_safe() {
        assert_eq!(
            ref_suffix("sha256:0123456789abcdef0123456789abcdef").unwrap(),
            "0123456789abcdef"
        );
        assert!(ref_suffix("nope").is_err());
    }
}
