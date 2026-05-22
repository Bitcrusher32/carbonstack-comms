use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::DeserializeBytes;

struct DeviceSetup {
    label: &'static str,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    key_package: KeyPackage,
}

fn main() {
    println!("CarbonStack OpenMLS two-message state-continuity probe");
    println!("Scope: local two-member group, two app messages, provider state continuity inside one run");
    println!("Integration: none");

    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();

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

    let group_id = GroupId::from_slice(b"carbonstack-openmls-minimal-group");

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

    let message_one = b"message one: hello from Alice over OpenMLS scratch";

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
        "Bob opened message one: {}",
        String::from_utf8_lossy(&opened_one)
    );

    println!("State continuity checkpoint:");
    println!("Alice epoch after message one: {:?}", alice_group.epoch());
    println!("Bob epoch after message one: {:?}", bob_group.epoch());
    println!("Bob member count after message one: {}", bob_group.members().count());

    println!("Reloading Alice group from Alice provider storage");
    let alice_group_id = alice_group.group_id().clone();
    let mut loaded_alice_group = MlsGroup::load(alice_provider.storage(), &alice_group_id)
        .expect("failed to load Alice group from provider storage")
        .expect("Alice group was not found in provider storage");

    println!("Reloading Bob group from Bob provider storage");
    let bob_group_id = bob_group.group_id().clone();
    let mut loaded_bob_group = MlsGroup::load(bob_provider.storage(), &bob_group_id)
        .expect("failed to load Bob group from provider storage")
        .expect("Bob group was not found in provider storage");

    println!("Loaded Alice epoch: {:?}", loaded_alice_group.epoch());
    println!("Loaded Bob epoch: {:?}", loaded_bob_group.epoch());
    println!("Loaded Alice member count: {}", loaded_alice_group.members().count());
    println!("Loaded Bob member count: {}", loaded_bob_group.members().count());

    assert_eq!(
        loaded_alice_group.members().count(),
        2,
        "Loaded Alice group should have exactly two members"
    );

    assert_eq!(
        loaded_bob_group.members().count(),
        2,
        "Loaded Bob group should have exactly two members"
    );

    let message_two = b"message two: storage reload check after processing message one";

    let opened_two = send_from_alice_to_bob(
        &alice_provider,
        &bob_provider,
        &alice.signer,
        &mut loaded_alice_group,
        &mut loaded_bob_group,
        message_two,
    );

    assert_eq!(
        opened_two,
        message_two,
        "Bob-opened second plaintext should match Alice plaintext"
    );

    println!(
        "Bob opened message two: {}",
        String::from_utf8_lossy(&opened_two)
    );

    println!("OpenMLS same-process storage reload probe succeeded");
    println!("Persistence conclusion: groups could be loaded from same-process provider storage and used for the second message.");
    println!("Next rung: identify real disk-backed provider storage/export strategy for process restart.");
}

fn make_device_setup(
    provider: &OpenMlsRustCrypto,
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

fn send_from_alice_to_bob(
    alice_provider: &OpenMlsRustCrypto,
    bob_provider: &OpenMlsRustCrypto,
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



