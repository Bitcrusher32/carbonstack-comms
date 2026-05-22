use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use serde_json::json;
use std::env;
use std::fs;
use std::fs::File;
use std::path::PathBuf;
use std::io::Write;
use tls_codec::DeserializeBytes;

const ALICE_STORAGE_NAME: &str = "carbonstack_openmls_alice";
const BOB_STORAGE_NAME: &str = "carbonstack_openmls_bob";
const ALICE_SIGNER_FILE_NAME: &str = "carbonstack_openmls_alice_signer.json";
const GROUP_ID_BYTES: &[u8] = b"carbonstack-openmls-minimal-group";

struct CarbonStackScratchProvider {
    crypto: RustCrypto,
    key_store: MemoryStorage,
}

impl Default for CarbonStackScratchProvider {
    fn default() -> Self {
        Self {
            crypto: RustCrypto::default(),
            key_store: MemoryStorage::default(),
        }
    }
}

impl OpenMlsProvider for CarbonStackScratchProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.key_store
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

struct DeviceSetup {
    label: &'static str,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    key_package: KeyPackage,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match mode {
        "phase-a" => phase_a(),
        "phase-b" => phase_b(),
        "fixtures" => fixtures(),
        _ => {
            println!("CarbonStack OpenMLS MemoryStorage persistence probe");
            println!("Usage:");
            println!("  cargo run -- phase-a");
            println!("  cargo run -- phase-b");
                println!("  cargo run -- fixtures");
            println!();
            println!("phase-a creates Alice/Bob MLS state, sends message one, and saves MemoryStorage files.");
            println!("phase-b loads fresh providers from MemoryStorage files, reloads groups, and sends message two.");
        }
    }
}


fn fixture_dir() -> PathBuf {
    PathBuf::from("fixtures").join("dev")
}

fn reset_fixture_dir() {
    let dir = fixture_dir();

    if dir.exists() {
        fs::remove_dir_all(&dir).expect("failed to remove existing fixture directory");
    }

    fs::create_dir_all(&dir).expect("failed to create fixture directory");
}

fn write_json_file(file_name: &str, value: serde_json::Value) {
    let path = fixture_dir().join(file_name);
    let file = File::create(&path).expect("failed to create fixture JSON file");
    serde_json::to_writer_pretty(file, &value).expect("failed to write fixture JSON");
    println!("Wrote fixture: {}", path.display());
}

fn append_event(value: serde_json::Value) {
    let path = fixture_dir().join("provider-events.jsonl");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("failed to open provider-events.jsonl");

    let line = serde_json::to_string(&value).expect("failed to serialize provider event");
    writeln!(file, "{}", line).expect("failed to append provider event");
}

fn bytes_len(bytes: &[u8]) -> usize {
    bytes.len()
}

fn phase_a() {
    println!("CarbonStack OpenMLS MemoryStorage persistence probe: phase-a");
    println!("Scope: create state, send/open message one, save Alice/Bob MemoryStorage files");
    println!("Integration: none");

    let alice_provider = CarbonStackScratchProvider::default();
    let bob_provider = CarbonStackScratchProvider::default();

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let alice = make_device_setup(&alice_provider, ciphersuite, "carbonstack-alice-device");
    let bob = make_device_setup(&bob_provider, ciphersuite, "carbonstack-bob-device");

    println!("Alice KeyPackage ready: {}", alice.label);
    println!("Bob KeyPackage ready: {}", bob.label);

    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();

    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let group_id = GroupId::from_slice(GROUP_ID_BYTES);

    let mut alice_group = MlsGroup::new_with_group_id(
        &alice_provider,
        &alice.signer,
        &create_config,
        group_id,
        alice.credential_with_key.clone(),
    )
    .expect("failed to create Alice MLS group");

    println!("Alice group created");
    println!("Alice initial epoch: {:?}", alice_group.epoch());
    println!("Alice initial member count: {}", alice_group.members().count());

    let (_commit, welcome_msg, group_info) = alice_group
        .add_members(&alice_provider, &alice.signer, &[bob.key_package.clone()])
        .expect("failed to add Bob to Alice MLS group");

    println!("Welcome MlsMessageOut produced for Bob");
    println!("GroupInfo produced with ratchet tree extension: {}", group_info.is_some());

    let welcome = match welcome_msg.body() {
        MlsMessageBodyOut::Welcome(welcome) => welcome.clone(),
        other => panic!("expected Welcome MlsMessageOut body, got: {:?}", other),
    };

    println!("Welcome extracted from MlsMessageOut for Bob");
    println!("Welcome encrypted secret count: {}", welcome.secrets().len());

    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("failed to merge Alice pending commit after adding Bob");

    println!("Alice pending commit merged");
    println!("Alice epoch after add: {:?}", alice_group.epoch());
    println!("Alice member count after add: {}", alice_group.members().count());

    let staged_welcome = StagedWelcome::new_from_welcome(
        &bob_provider,
        &join_config,
        welcome,
        None,
    )
    .expect("failed to stage Bob Welcome");

    println!("Bob staged Welcome");
    println!(
        "Bob staged Welcome member count: {}",
        staged_welcome.members().count()
    );

    let mut bob_group = staged_welcome
        .into_group(&bob_provider)
        .expect("failed to turn staged Welcome into Bob MLS group");

    println!("Bob joined group from Welcome");
    println!("Bob epoch after join: {:?}", bob_group.epoch());
    println!("Bob member count after join: {}", bob_group.members().count());

    assert_eq!(
        alice_group.members().count(),
        2,
        "Alice group should have exactly two members after adding Bob"
    );

    assert_eq!(
        bob_group.members().count(),
        2,
        "Bob group should have exactly two members after joining"
    );

    let message_one = b"phase-a message one: hello before MemoryStorage save";

    let opened_one = send_from_alice_to_bob(
        &alice_provider,
        &bob_provider,
        &alice.signer,
        &mut alice_group,
        &mut bob_group,
        message_one,
    );

    assert_eq!(
        opened_one,
        message_one,
        "Bob-opened first plaintext should match Alice plaintext"
    );

    println!(
        "Bob opened phase-a message one: {}",
        String::from_utf8_lossy(&opened_one)
    );

    println!("Saving Alice signer file");
    save_alice_signer(&alice.signer);

    println!("Saving Alice MemoryStorage file");
    alice_provider
        .key_store
        .save(ALICE_STORAGE_NAME.to_string())
        .expect("failed to save Alice MemoryStorage");

    println!("Saving Bob MemoryStorage file");
    bob_provider
        .key_store
        .save(BOB_STORAGE_NAME.to_string())
        .expect("failed to save Bob MemoryStorage");

    println!("Phase A succeeded");
    println!("Saved MemoryStorage files under the OS temp directory using OpenMLS memory-storage persistence helpers.");
    println!("Next: run cargo run -- phase-b");
}

fn phase_b() {
    println!("CarbonStack OpenMLS MemoryStorage persistence probe: phase-b");
    println!("Scope: load fresh providers from saved MemoryStorage files, reload groups, send/open message two");
    println!("Integration: none");

    let mut alice_provider = CarbonStackScratchProvider::default();
    let mut bob_provider = CarbonStackScratchProvider::default();

    println!("Loading Alice MemoryStorage file");
    alice_provider
        .key_store
        .load(ALICE_STORAGE_NAME.to_string())
        .expect("failed to load Alice MemoryStorage");

    println!("Loading Bob MemoryStorage file");
    bob_provider
        .key_store
        .load(BOB_STORAGE_NAME.to_string())
        .expect("failed to load Bob MemoryStorage");

    let group_id = GroupId::from_slice(GROUP_ID_BYTES);

    println!("Reloading Alice group from loaded Alice provider storage");
    let mut alice_group = MlsGroup::load(alice_provider.storage(), &group_id)
        .expect("failed to load Alice group from loaded provider storage")
        .expect("Alice group was not found in loaded provider storage");

    println!("Reloading Bob group from loaded Bob provider storage");
    let mut bob_group = MlsGroup::load(bob_provider.storage(), &group_id)
        .expect("failed to load Bob group from loaded provider storage")
        .expect("Bob group was not found in loaded provider storage");

    println!("Loaded Alice epoch: {:?}", alice_group.epoch());
    println!("Loaded Bob epoch: {:?}", bob_group.epoch());
    println!("Loaded Alice member count: {}", alice_group.members().count());
    println!("Loaded Bob member count: {}", bob_group.members().count());

    assert_eq!(
        alice_group.members().count(),
        2,
        "Loaded Alice group should have exactly two members"
    );

    assert_eq!(
        bob_group.members().count(),
        2,
        "Loaded Bob group should have exactly two members"
    );

    let alice_signer = load_alice_signer();

    println!("Phase-b loaded Alice signer from temp file.");

    let message_two = b"phase-b message two: hello after MemoryStorage load";

    let opened_two = send_from_alice_to_bob(
        &alice_provider,
        &bob_provider,
        &alice_signer,
        &mut alice_group,
        &mut bob_group,
        message_two,
    );

    assert_eq!(
        opened_two,
        message_two,
        "Bob-opened second plaintext should match Alice plaintext"
    );

    println!(
        "Bob opened phase-b message two: {}",
        String::from_utf8_lossy(&opened_two)
    );

    println!("Phase B succeeded");
    println!("MemoryStorage file load plus MlsGroup::load allowed a second message after fresh provider construction.");
}


fn fixtures() {
    println!("CarbonStack OpenMLS provider fixture mode");
    println!("Scope: sanitized provider-contract summaries only");
    println!("Integration: none");

    reset_fixture_dir();

    let alice_provider = CarbonStackScratchProvider::default();
    let bob_provider = CarbonStackScratchProvider::default();

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let alice = make_device_setup(&alice_provider, ciphersuite, "carbonstack-alice-device");
    let bob = make_device_setup(&bob_provider, ciphersuite, "carbonstack-bob-device");

    let group_id = GroupId::from_slice(GROUP_ID_BYTES);

    write_json_file(
        "provider-summary.json",
        json!({
            "fixture_version": "provider-fixture-contract/v0",
            "provider_name": "openmls",
            "provider_mode": "rust-only-scratch",
            "implementation": "CarbonStackScratchProvider",
            "ciphersuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_id_label": String::from_utf8_lossy(GROUP_ID_BYTES),
            "security_level": "dev-only sanitized summary; not production crypto integration",
            "warnings": [
                "OpenMLS is not wired into CarbonStackComms",
                "fixtures are not production secrets",
                "provider storage and signer JSON are intentionally not written into fixtures"
            ]
        }),
    );

    append_event(json!({
        "event": "provider.fixture.started",
        "provider": "openmls",
        "mode": "fixtures"
    }));

    let alice_kp_hash = alice
        .key_package
        .hash_ref(alice_provider.crypto())
        .expect("failed to hash Alice KeyPackage");
    let bob_kp_hash = bob
        .key_package
        .hash_ref(bob_provider.crypto())
        .expect("failed to hash Bob KeyPackage");

    write_json_file(
        "alice-device-summary.json",
        json!({
            "device_label": alice.label,
            "role": "alice",
            "public_key_package_hash_ref_length": alice_kp_hash.as_slice().len(),
            "private_material_included": false
        }),
    );

    write_json_file(
        "bob-device-summary.json",
        json!({
            "device_label": bob.label,
            "role": "bob",
            "public_key_package_hash_ref_length": bob_kp_hash.as_slice().len(),
            "private_material_included": false
        }),
    );

    append_event(json!({
        "event": "provider.public_bundle.created",
        "device": "alice",
        "hash_ref_length": alice_kp_hash.as_slice().len()
    }));

    append_event(json!({
        "event": "provider.public_bundle.created",
        "device": "bob",
        "hash_ref_length": bob_kp_hash.as_slice().len()
    }));

    write_json_file(
        "alice-public-setup-summary.json",
        json!({
            "device": "alice",
            "public_setup_type": "KeyPackage",
            "hash_ref_length": alice_kp_hash.as_slice().len(),
            "private_material_included": false
        }),
    );

    write_json_file(
        "bob-public-setup-summary.json",
        json!({
            "device": "bob",
            "public_setup_type": "KeyPackage",
            "hash_ref_length": bob_kp_hash.as_slice().len(),
            "private_material_included": false
        }),
    );

    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();

    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let mut alice_group = MlsGroup::new_with_group_id(
        &alice_provider,
        &alice.signer,
        &create_config,
        group_id,
        alice.credential_with_key.clone(),
    )
    .expect("failed to create Alice MLS group");

    append_event(json!({
        "event": "conversation.created",
        "creator": "alice",
        "epoch": format!("{:?}", alice_group.epoch()),
        "member_count": alice_group.members().count()
    }));

    write_conversation_summary(
        "conversation-before-message.json",
        "before_add",
        &alice_group,
        None,
    );

    let (_commit, welcome_msg, group_info) = alice_group
        .add_members(&alice_provider, &alice.signer, &[bob.key_package.clone()])
        .expect("failed to add Bob to Alice MLS group");

    let welcome = match welcome_msg.body() {
        MlsMessageBodyOut::Welcome(welcome) => welcome.clone(),
        other => panic!("expected Welcome MlsMessageOut body, got: {:?}", other),
    };

    write_json_file(
        "welcome-summary.json",
        json!({
            "join_material_type": "Welcome",
            "encrypted_secret_count": welcome.secrets().len(),
            "group_info_present": group_info.is_some(),
            "private_material_included": false
        }),
    );

    append_event(json!({
        "event": "conversation.welcome.created",
        "encrypted_secret_count": welcome.secrets().len(),
        "group_info_present": group_info.is_some()
    }));

    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("failed to merge Alice pending commit after adding Bob");

    append_event(json!({
        "event": "conversation.member_added",
        "adder": "alice",
        "added": "bob",
        "alice_epoch_after_merge": format!("{:?}", alice_group.epoch()),
        "alice_member_count": alice_group.members().count()
    }));

    let staged_welcome = StagedWelcome::new_from_welcome(
        &bob_provider,
        &join_config,
        welcome,
        None,
    )
    .expect("failed to stage Bob Welcome");

    append_event(json!({
        "event": "conversation.welcome.staged",
        "device": "bob",
        "member_count": staged_welcome.members().count()
    }));

    let mut bob_group = staged_welcome
        .into_group(&bob_provider)
        .expect("failed to turn staged Welcome into Bob MLS group");

    append_event(json!({
        "event": "conversation.joined",
        "device": "bob",
        "epoch": format!("{:?}", bob_group.epoch()),
        "member_count": bob_group.members().count()
    }));

    write_conversation_summary(
        "conversation-after-message-one.json",
        "after_join_before_message_one",
        &alice_group,
        Some(&bob_group),
    );

    let message_one = b"fixture message one: provider contract sample";

    let app_message_out_one = alice_group
        .create_message(&alice_provider, &alice.signer, message_one)
        .expect("failed to create fixture message one");

    let app_message_bytes_one = app_message_out_one
        .to_bytes()
        .expect("failed to serialize fixture message one");

    let opened_one = process_message_for_fixture(
        &bob_provider,
        &mut bob_group,
        &app_message_bytes_one,
    );

    assert_eq!(opened_one, message_one);

    write_json_file(
        "message-one-summary.json",
        json!({
            "message_label": "message-one",
            "content_type": "Application",
            "protected_byte_length": bytes_len(&app_message_bytes_one),
            "plaintext_length": message_one.len(),
            "plaintext_sample": String::from_utf8_lossy(message_one),
            "private_material_included": false
        }),
    );

    append_event(json!({
        "event": "message.protected",
        "sender": "alice",
        "message_label": "message-one",
        "protected_byte_length": bytes_len(&app_message_bytes_one)
    }));

    append_event(json!({
        "event": "message.opened",
        "receiver": "bob",
        "message_label": "message-one",
        "plaintext_length": message_one.len()
    }));

    let alice_group_id = alice_group.group_id().clone();
    let mut loaded_alice_group = MlsGroup::load(alice_provider.storage(), &alice_group_id)
        .expect("failed to load Alice group from provider storage")
        .expect("Alice group was not found in provider storage");

    let bob_group_id = bob_group.group_id().clone();
    let mut loaded_bob_group = MlsGroup::load(bob_provider.storage(), &bob_group_id)
        .expect("failed to load Bob group from provider storage")
        .expect("Bob group was not found in provider storage");

    write_conversation_summary(
        "conversation-after-reload.json",
        "after_same_process_reload",
        &loaded_alice_group,
        Some(&loaded_bob_group),
    );

    append_event(json!({
        "event": "conversation.loaded",
        "scope": "same_process_provider_storage",
        "alice_epoch": format!("{:?}", loaded_alice_group.epoch()),
        "bob_epoch": format!("{:?}", loaded_bob_group.epoch())
    }));

    let message_two = b"fixture message two: after provider storage reload";

    let app_message_out_two = loaded_alice_group
        .create_message(&alice_provider, &alice.signer, message_two)
        .expect("failed to create fixture message two");

    let app_message_bytes_two = app_message_out_two
        .to_bytes()
        .expect("failed to serialize fixture message two");

    let opened_two = process_message_for_fixture(
        &bob_provider,
        &mut loaded_bob_group,
        &app_message_bytes_two,
    );

    assert_eq!(opened_two, message_two);

    write_json_file(
        "message-two-summary.json",
        json!({
            "message_label": "message-two",
            "content_type": "Application",
            "protected_byte_length": bytes_len(&app_message_bytes_two),
            "plaintext_length": message_two.len(),
            "plaintext_sample": String::from_utf8_lossy(message_two),
            "private_material_included": false
        }),
    );

    write_conversation_summary(
        "conversation-after-message-two.json",
        "after_message_two",
        &loaded_alice_group,
        Some(&loaded_bob_group),
    );

    append_event(json!({
        "event": "message.protected",
        "sender": "alice",
        "message_label": "message-two",
        "protected_byte_length": bytes_len(&app_message_bytes_two)
    }));

    append_event(json!({
        "event": "message.opened",
        "receiver": "bob",
        "message_label": "message-two",
        "plaintext_length": message_two.len()
    }));

    write_json_file(
        "invalid-signature-error.json",
        json!({
            "error_fixture": "invalid-signature-after-signer-mismatch",
            "source_observation": "phase-b initially failed when Alice used a fresh signer after reload",
            "openmls_error": "ValidationError(InvalidSignature)",
            "carbonstack_mapping_candidate": "provider.signature.invalid",
            "suggested_trust_action": [
                "block message",
                "warn user",
                "append trust event",
                "require reverify if identity changed"
            ],
            "private_material_included": false
        }),
    );

    append_event(json!({
        "event": "provider.fixture.completed",
        "status": "success",
        "private_material_included": false
    }));

    println!("Fixture mode succeeded");
    println!("Sanitized fixtures written to {}", fixture_dir().display());
}

fn write_conversation_summary(
    file_name: &str,
    checkpoint: &str,
    alice_group: &MlsGroup,
    bob_group: Option<&MlsGroup>,
) {
    write_json_file(
        file_name,
        json!({
            "checkpoint": checkpoint,
            "group_id_label": String::from_utf8_lossy(GROUP_ID_BYTES),
            "alice_epoch": format!("{:?}", alice_group.epoch()),
            "alice_member_count": alice_group.members().count(),
            "bob_epoch": bob_group.map(|group| format!("{:?}", group.epoch())),
            "bob_member_count": bob_group.map(|group| group.members().count()),
            "private_material_included": false
        }),
    );
}

fn process_message_for_fixture(
    bob_provider: &CarbonStackScratchProvider,
    bob_group: &mut MlsGroup,
    app_message_bytes: &[u8],
) -> Vec<u8> {
    let app_message_in = MlsMessageIn::tls_deserialize_exact_bytes(app_message_bytes)
        .expect("failed to deserialize fixture application message as MlsMessageIn");

    let protocol_message = app_message_in
        .try_into_protocol_message()
        .expect("failed to convert fixture MlsMessageIn into ProtocolMessage");

    let processed_message = bob_group
        .process_message(bob_provider, protocol_message)
        .expect("Bob failed to process fixture application message");

    match processed_message.into_content() {
        ProcessedMessageContent::ApplicationMessage(application_message) => {
            application_message.into_bytes()
        }
        other => panic!("expected fixture application message content, got: {:?}", other),
    }
}

fn make_device_setup(
    provider: &CarbonStackScratchProvider,
    ciphersuite: Ciphersuite,
    label: &'static str,
) -> DeviceSetup {
    let credential = BasicCredential::new(label.as_bytes().to_vec());

    let signer = SignatureKeyPair::new(ciphersuite.into())
        .expect("failed to create OpenMLS basic credential signature key pair");

    let public_signature_key = signer.to_public_vec();

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: public_signature_key.into(),
    };

    let key_package_bundle = KeyPackage::builder()
        .build(
            ciphersuite,
            provider,
            &signer,
            credential_with_key.clone(),
        )
        .expect("failed to build OpenMLS KeyPackageBundle");

    let key_package = key_package_bundle.key_package().clone();

    let hash_ref = key_package
        .hash_ref(provider.crypto())
        .expect("failed to compute KeyPackage hash reference");

    println!(
        "{} KeyPackage hash reference length: {}",
        label,
        hash_ref.as_slice().len()
    );

    DeviceSetup {
        label,
        signer,
        credential_with_key,
        key_package,
    }
}


fn temp_file_path(file_name: &str) -> PathBuf {
    env::temp_dir().join(file_name)
}

fn save_alice_signer(signer: &SignatureKeyPair) {
    let path = temp_file_path(ALICE_SIGNER_FILE_NAME);
    let file = File::create(&path).expect("failed to create Alice signer file");
    serde_json::to_writer_pretty(file, signer).expect("failed to serialize Alice signer");
    println!("Saved Alice signer file: {}", path.display());
}

fn load_alice_signer() -> SignatureKeyPair {
    let path = temp_file_path(ALICE_SIGNER_FILE_NAME);
    let file = File::open(&path).expect("failed to open Alice signer file");
    let signer: SignatureKeyPair =
        serde_json::from_reader(file).expect("failed to deserialize Alice signer");
    println!("Loaded Alice signer file: {}", path.display());
    signer
}

fn send_from_alice_to_bob(
    alice_provider: &CarbonStackScratchProvider,
    bob_provider: &CarbonStackScratchProvider,
    alice_signer: &SignatureKeyPair,
    alice_group: &mut MlsGroup,
    bob_group: &mut MlsGroup,
    plaintext: &[u8],
) -> Vec<u8> {
    let app_message_out = alice_group
        .create_message(alice_provider, alice_signer, plaintext)
        .expect("failed to create Alice application message");

    println!("Alice created application message");

    let app_message_bytes = app_message_out
        .to_bytes()
        .expect("failed to serialize Alice application message");

    let app_message_in = MlsMessageIn::tls_deserialize_exact_bytes(&app_message_bytes)
        .expect("failed to deserialize Alice application message as MlsMessageIn");

    let protocol_message = app_message_in
        .try_into_protocol_message()
        .expect("failed to convert MlsMessageIn into ProtocolMessage");

    println!("Application message converted to ProtocolMessage");
    println!("Protocol message epoch: {:?}", protocol_message.epoch());
    println!("Protocol message content type: {:?}", protocol_message.content_type());

    let processed_message = bob_group
        .process_message(bob_provider, protocol_message)
        .expect("Bob failed to process Alice application message");

    println!("Bob processed application message");
    println!("Processed message epoch: {:?}", processed_message.epoch());
    println!("Processed message sender: {:?}", processed_message.sender());

    match processed_message.into_content() {
        ProcessedMessageContent::ApplicationMessage(application_message) => {
            application_message.into_bytes()
        }
        other => panic!("expected application message content, got: {:?}", other),
    }
}









