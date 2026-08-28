use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::fs::symlink;

use gooir_capability::canonical_digest;
use gooir_capability::protocol::{ConformanceSuiteId, ImplementationId};
use gooir_capability::{
    CapabilityId, CapabilitySpec, DialectId, InputPort, OutputPort, PortName, ValueKindId,
};
use gooir_package::{
    ConformanceSuiteDeclaration, DialectDeclaration, PackageId, PackageManifest, ResourceName,
    ValueKindDeclaration, write_manifest,
};
use gooir_toolchain::{
    AttesterArtifactBinding, InstalledToolchain, LockedPackage, PackageRecipe,
    PublicationDurability, ResourceInput, ToolchainError, ToolchainImageBuilder, ToolchainLimits,
    ToolchainLock, ToolchainLockDigest, ToolchainPublication,
};
use serde_json::json;

const PACKAGE: &str = "org.example.toolchain";
const VERSION: &str = "1.0.0";
const PROVIDER_BYTES: &[u8] = b"exact-provider-artifact";
const ATTESTER_BYTES: &[u8] = b"independent-attester-artifact";

fn package_id() -> PackageId {
    PackageId::parse(format!("{PACKAGE}@{VERSION}")).unwrap()
}

fn capability_id() -> CapabilityId {
    CapabilityId::new(PACKAGE, "compile", VERSION)
}

fn suite_id() -> ConformanceSuiteId {
    ConformanceSuiteId::new(PACKAGE, "compile", VERSION)
}

fn provider_implementation() -> ImplementationId {
    ImplementationId::new("org.example.provider", "compile", VERSION)
}

fn attester_implementation() -> ImplementationId {
    ImplementationId::new("org.example.attester", "compile", VERSION)
}

fn provider_resource() -> ResourceName {
    ResourceName::parse("provider").unwrap()
}

fn attester_resource() -> ResourceName {
    ResourceName::parse("attester").unwrap()
}

fn authoring_manifest() -> PackageManifest {
    let dialect = DialectId::new(PACKAGE, VERSION);
    let input = ValueKindId::in_dialect(dialect.clone(), "input");
    let output = ValueKindId::in_dialect(dialect.clone(), "output");
    PackageManifest::new(
        package_id(),
        Vec::new(),
        Vec::new(),
        vec![DialectDeclaration {
            id: dialect,
            value_kinds: vec![
                ValueKindDeclaration {
                    id: input.clone(),
                    schema: None,
                    extensions: BTreeMap::new(),
                },
                ValueKindDeclaration {
                    id: output.clone(),
                    schema: None,
                    extensions: BTreeMap::new(),
                },
            ],
            extensions: BTreeMap::new(),
        }],
        vec![ConformanceSuiteDeclaration {
            id: suite_id(),
            extensions: BTreeMap::new(),
        }],
        vec![CapabilitySpec {
            id: capability_id(),
            input_ports: vec![InputPort::complete(
                PortName::parse("input").unwrap(),
                input,
            )],
            output_ports: vec![OutputPort::new(PortName::parse("output").unwrap(), output)],
            default_conformance_suite: suite_id().to_string(),
            extensions: BTreeMap::new(),
        }],
        Vec::new(),
        BTreeMap::new(),
    )
    .unwrap()
}

fn recipe(
    provider: ResourceInput,
    attester_bytes: &[u8],
    provider_implementation: ImplementationId,
    attester_implementation: ImplementationId,
) -> PackageRecipe {
    PackageRecipe::from_manifest("toolchain", authoring_manifest())
        .unwrap()
        .with_resource(provider)
        .unwrap()
        .with_resource(ResourceInput::bytes(
            attester_resource(),
            "bin/attester",
            "application/octet-stream",
            attester_bytes,
        ))
        .unwrap()
        .with_provider(
            provider_implementation,
            capability_id(),
            provider_resource(),
        )
        .unwrap()
        .with_attester(suite_id(), attester_implementation, attester_resource())
        .unwrap()
}

fn bytes_recipe() -> PackageRecipe {
    recipe(
        ResourceInput::bytes(
            provider_resource(),
            "bin/provider",
            "application/octet-stream",
            PROVIDER_BYTES,
        ),
        ATTESTER_BYTES,
        provider_implementation(),
        attester_implementation(),
    )
}

fn builder(recipe: PackageRecipe) -> ToolchainImageBuilder {
    ToolchainImageBuilder::new().with_package(recipe).unwrap()
}

fn assert_synced(publication: &ToolchainPublication) {
    assert_eq!(
        publication.durability(),
        &PublicationDurability::DirectorySynchronized
    );
}

#[test]
fn stages_measured_offers_and_host_only_attesters_then_reloads() {
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("image");
    let limits = ToolchainLimits::default();

    let publication = builder(bytes_recipe())
        .publish_create(&destination, limits)
        .unwrap();
    let installed = InstalledToolchain::load(&destination, limits).unwrap();

    assert_eq!(installed.lock(), publication.lock());
    assert_eq!(
        publication.durability(),
        &PublicationDurability::DirectorySynchronized
    );
    assert!(installed.registry().package(&package_id()).is_some());
    let offers = installed.registry().offers().collect::<Vec<_>>();
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].implementation, provider_implementation());
    assert_eq!(offers[0].capability, capability_id());
    assert_eq!(
        installed
            .registry()
            .offer_artifact(&offers[0].offer_id)
            .unwrap()
            .bytes(),
        PROVIDER_BYTES
    );
    let [binding] = installed.local_attester_bindings() else {
        panic!("one host-only attester binding must be retained")
    };
    assert_eq!(binding.authority.suite, suite_id());
    assert_eq!(
        binding.authority.attester.implementation,
        attester_implementation()
    );
    assert_eq!(
        installed
            .registry()
            .resource(&binding.package, &binding.resource)
            .unwrap()
            .bytes(),
        ATTESTER_BYTES
    );
    assert!(
        installed
            .registry()
            .offers()
            .all(|offer| { offer.implementation != binding.authority.attester.implementation })
    );
}

#[test]
fn copied_image_survives_disappearing_source_artifact() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("provider-final");
    fs::write(&source, PROVIDER_BYTES).unwrap();
    let destination = temporary.path().join("image");
    let recipe = recipe(
        ResourceInput::file(
            provider_resource(),
            "bin/provider",
            "application/octet-stream",
            &source,
        ),
        ATTESTER_BYTES,
        provider_implementation(),
        attester_implementation(),
    );

    assert_synced(
        &builder(recipe)
            .publish_create(&destination, ToolchainLimits::default())
            .unwrap(),
    );
    fs::remove_file(source).unwrap();

    let installed = InstalledToolchain::load(destination, ToolchainLimits::default()).unwrap();
    assert_eq!(
        installed
            .registry()
            .offers()
            .next()
            .and_then(|offer| installed.registry().offer_artifact(&offer.offer_id))
            .unwrap()
            .bytes(),
        PROVIDER_BYTES
    );
}

#[test]
fn refuses_existing_destination_and_retains_it() {
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("image");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("keep"), b"operator data").unwrap();

    let error = builder(bytes_recipe())
        .publish_create(&destination, ToolchainLimits::default())
        .unwrap_err();

    assert!(matches!(error, ToolchainError::DestinationExists(path) if path == destination));
    assert_eq!(
        fs::read(destination.join("keep")).unwrap(),
        b"operator data"
    );
}

#[test]
fn altered_copied_resource_is_refused_on_fresh_load() {
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("image");
    assert_synced(
        &builder(bytes_recipe())
            .publish_create(&destination, ToolchainLimits::default())
            .unwrap(),
    );
    let provider = destination.join("toolchain/bin/provider");
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&provider, b"substituted-provider-artifact").unwrap();

    assert!(matches!(
        InstalledToolchain::load(destination, ToolchainLimits::default()),
        Err(ToolchainError::PackageLoad(_))
    ));
}

#[test]
fn self_attestation_by_implementation_or_artifact_is_refused() {
    let temporary = tempfile::tempdir().unwrap();
    let same_implementation = recipe(
        ResourceInput::bytes(
            provider_resource(),
            "bin/provider",
            "application/octet-stream",
            PROVIDER_BYTES,
        ),
        ATTESTER_BYTES,
        provider_implementation(),
        provider_implementation(),
    );
    assert!(matches!(
        builder(same_implementation).publish_create(
            temporary.path().join("same-implementation"),
            ToolchainLimits::default()
        ),
        Err(ToolchainError::AttesterNotIndependent { .. })
    ));

    let same_artifact = recipe(
        ResourceInput::bytes(
            provider_resource(),
            "bin/provider",
            "application/octet-stream",
            PROVIDER_BYTES,
        ),
        PROVIDER_BYTES,
        provider_implementation(),
        attester_implementation(),
    );
    assert!(matches!(
        builder(same_artifact).publish_create(
            temporary.path().join("same-artifact"),
            ToolchainLimits::default()
        ),
        Err(ToolchainError::AttesterNotIndependent { .. })
    ));
}

#[test]
fn package_directory_must_be_one_safe_relative_component() {
    for directory in ["", ".", "..", "nested/package", "C:package", "bad\\path"] {
        assert!(matches!(
            PackageRecipe::from_manifest(directory, authoring_manifest()),
            Err(ToolchainError::UnsafeRelativePath(_))
        ));
    }
}

#[test]
fn duplicate_resource_provider_and_attester_bindings_are_refused() {
    let recipe = PackageRecipe::from_manifest("toolchain", authoring_manifest())
        .unwrap()
        .with_resource(ResourceInput::bytes(
            provider_resource(),
            "bin/provider",
            "application/octet-stream",
            PROVIDER_BYTES,
        ))
        .unwrap();
    assert!(matches!(
        recipe.clone().with_resource(ResourceInput::bytes(
            provider_resource(),
            "bin/other-provider",
            "application/octet-stream",
            PROVIDER_BYTES,
        )),
        Err(ToolchainError::DuplicateResource(_))
    ));

    let recipe = recipe
        .with_provider(
            provider_implementation(),
            capability_id(),
            provider_resource(),
        )
        .unwrap();
    assert!(matches!(
        recipe.clone().with_provider(
            provider_implementation(),
            capability_id(),
            provider_resource(),
        ),
        Err(ToolchainError::DuplicateProviderBinding { .. })
    ));

    let recipe = recipe
        .with_attester(suite_id(), attester_implementation(), provider_resource())
        .unwrap();
    assert!(matches!(
        recipe.with_attester(suite_id(), attester_implementation(), provider_resource(),),
        Err(ToolchainError::DuplicateAttesterRecipe { .. })
    ));
}

#[test]
fn duplicate_logical_authority_under_two_resources_is_refused() {
    let duplicate_resource = ResourceName::parse("attester-copy").unwrap();
    let recipe = bytes_recipe()
        .with_resource(ResourceInput::bytes(
            duplicate_resource.clone(),
            "bin/attester-copy",
            "application/octet-stream",
            ATTESTER_BYTES,
        ))
        .unwrap()
        .with_attester(suite_id(), attester_implementation(), duplicate_resource)
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();

    assert!(matches!(
        builder(recipe).publish_create(
            temporary.path().join("duplicate-authority"),
            ToolchainLimits::default()
        ),
        Err(ToolchainError::DuplicateAttesterAuthority { .. })
    ));
}

#[test]
fn self_attestation_is_refused_even_for_a_nondefault_suite() {
    let recipe = bytes_recipe()
        .with_attester(
            ConformanceSuiteId::new(PACKAGE, "another-suite", VERSION),
            ImplementationId::new("org.example.attester", "another-suite", VERSION),
            provider_resource(),
        )
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();

    assert!(matches!(
        builder(recipe).publish_create(
            temporary.path().join("cross-suite-self-attestation"),
            ToolchainLimits::default()
        ),
        Err(ToolchainError::AttesterNotIndependent { .. })
    ));
}

#[test]
fn altered_lock_coordinates_are_refused_before_loading_packages() {
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("image");
    assert_synced(
        &builder(bytes_recipe())
            .publish_create(&destination, ToolchainLimits::default())
            .unwrap(),
    );
    let lock_path = destination.join(gooir_toolchain::TOOLCHAIN_LOCK_FILE);
    let mut lock: serde_json::Value =
        serde_json::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
    lock["packages"][0]["relative_directory"] = serde_json::json!("substituted-package");
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&lock_path, serde_json::to_vec(&lock).unwrap()).unwrap();

    assert!(matches!(
        InstalledToolchain::load(destination, ToolchainLimits::default()),
        Err(ToolchainError::LockDigestMismatch { .. })
    ));
}

#[test]
fn self_consistent_attester_resource_coordinate_substitution_is_refused() {
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("image");
    let publication = builder(bytes_recipe())
        .publish_create(&destination, ToolchainLimits::default())
        .unwrap();
    let mut lock = publication.into_lock();
    lock.attesters[0].resource = ResourceName::parse("substituted-attester").unwrap();
    recompute_lock_digest(&mut lock);
    let lock_path = destination.join(gooir_toolchain::TOOLCHAIN_LOCK_FILE);
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&lock_path, lock.to_canonical_json().unwrap()).unwrap();

    assert!(matches!(
        InstalledToolchain::load(destination, ToolchainLimits::default()),
        Err(ToolchainError::MissingAttesterResource { .. })
    ));
}

#[test]
fn rewritten_valid_manifest_is_refused_against_the_locked_digest() {
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("image");
    assert_synced(
        &builder(bytes_recipe())
            .publish_create(&destination, ToolchainLimits::default())
            .unwrap(),
    );
    let manifest_path = destination.join("toolchain/gooir-package.json");
    let original = gooir_package::read_manifest(
        std::str::from_utf8(&fs::read(&manifest_path).unwrap()).unwrap(),
    )
    .unwrap();
    let altered = PackageManifest::new(
        original.package,
        original.dependencies,
        original.resources,
        original.dialects,
        original.conformance_suites,
        original.capabilities,
        original.implementation_offers,
        BTreeMap::from([("x.test/substitution".to_owned(), json!(true))]),
    )
    .unwrap();
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&manifest_path, write_manifest(&altered).unwrap()).unwrap();

    assert!(matches!(
        InstalledToolchain::load(destination, ToolchainLimits::default()),
        Err(ToolchainError::LockedPackageMismatch { .. })
    ));
}

#[test]
fn unsafe_resource_path_and_symlink_source_are_refused_without_publication() {
    let temporary = tempfile::tempdir().unwrap();
    let unsafe_destination = temporary.path().join("unsafe-path");
    let unsafe_recipe = PackageRecipe::from_manifest("toolchain", authoring_manifest())
        .unwrap()
        .with_resource(ResourceInput::bytes(
            provider_resource(),
            "../escape",
            "application/octet-stream",
            PROVIDER_BYTES,
        ))
        .unwrap();
    assert!(matches!(
        builder(unsafe_recipe).publish_create(&unsafe_destination, ToolchainLimits::default()),
        Err(ToolchainError::Manifest(_))
    ));
    assert!(!unsafe_destination.exists());

    let source = temporary.path().join("provider-source");
    let source_link = temporary.path().join("provider-link");
    fs::write(&source, PROVIDER_BYTES).unwrap();
    symlink(&source, &source_link).unwrap();
    let symlink_destination = temporary.path().join("symlink-source");
    let symlink_recipe = PackageRecipe::from_manifest("toolchain", authoring_manifest())
        .unwrap()
        .with_resource(ResourceInput::file(
            provider_resource(),
            "bin/provider",
            "application/octet-stream",
            source_link,
        ))
        .unwrap();
    assert!(matches!(
        builder(symlink_recipe).publish_create(&symlink_destination, ToolchainLimits::default()),
        Err(ToolchainError::Filesystem { .. })
    ));
    assert!(!symlink_destination.exists());
}

fn recompute_lock_digest(lock: &mut ToolchainLock) {
    #[derive(serde::Serialize)]
    struct LockBody<'lock> {
        protocol: &'lock str,
        packages: &'lock [LockedPackage],
        attesters: &'lock [AttesterArtifactBinding],
    }

    let digest = canonical_digest(&LockBody {
        protocol: &lock.protocol,
        packages: &lock.packages,
        attesters: &lock.attesters,
    })
    .unwrap();
    lock.content_digest = ToolchainLockDigest::parse(digest).unwrap();
}

#[test]
fn offer_attester_and_authority_extensions_survive_publication() {
    let resource_extensions =
        BTreeMap::from([("x.test/resource".to_owned(), json!({"kind": "binary"}))]);
    let offer_extensions =
        BTreeMap::from([("x.test/offer".to_owned(), json!({"profile": "debug"}))]);
    let attester_extensions =
        BTreeMap::from([("x.test/attester".to_owned(), json!(["independent"]))]);
    let authority_extensions =
        BTreeMap::from([("x.test/authority".to_owned(), json!({"policy": 1}))]);
    let recipe = PackageRecipe::from_manifest("toolchain", authoring_manifest())
        .unwrap()
        .with_resource(
            ResourceInput::bytes(
                provider_resource(),
                "bin/provider",
                "application/octet-stream",
                PROVIDER_BYTES,
            )
            .with_extensions(resource_extensions.clone()),
        )
        .unwrap()
        .with_resource(ResourceInput::bytes(
            attester_resource(),
            "bin/attester",
            "application/octet-stream",
            ATTESTER_BYTES,
        ))
        .unwrap()
        .with_provider_extensions(
            provider_implementation(),
            capability_id(),
            provider_resource(),
            offer_extensions.clone(),
        )
        .unwrap()
        .with_attester_extensions(
            suite_id(),
            attester_implementation(),
            attester_resource(),
            attester_extensions.clone(),
            authority_extensions.clone(),
        )
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("image");
    assert_synced(
        &builder(recipe)
            .publish_create(&destination, ToolchainLimits::default())
            .unwrap(),
    );
    let installed = InstalledToolchain::load(destination, ToolchainLimits::default()).unwrap();

    assert_eq!(
        installed.registry().offers().next().unwrap().extensions,
        offer_extensions
    );
    assert_eq!(
        installed
            .registry()
            .package(&package_id())
            .unwrap()
            .manifest()
            .resources
            .iter()
            .find(|resource| resource.name == provider_resource())
            .unwrap()
            .extensions,
        resource_extensions
    );
    let [binding] = installed.local_attester_bindings() else {
        panic!("one attester must be installed")
    };
    assert_eq!(binding.authority.attester.extensions, attester_extensions);
    assert_eq!(binding.authority.extensions, authority_extensions);
}

#[test]
fn image_budget_caps_each_remaining_package_before_resource_read() {
    let temporary = tempfile::tempdir().unwrap();
    let first_source = temporary.path().join("first-resource");
    let second_source = temporary.path().join("second-resource");
    fs::write(&first_source, b"1234").unwrap();
    fs::write(&second_source, b"5678").unwrap();
    let package = |id: &str, directory: &str, resource: &str, source: &std::path::Path| {
        PackageRecipe::from_manifest(
            directory,
            PackageManifest::new(
                PackageId::parse(format!("org.example.{id}@{VERSION}")).unwrap(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                BTreeMap::new(),
            )
            .unwrap(),
        )
        .unwrap()
        .with_resource(ResourceInput::file(
            ResourceName::parse(resource).unwrap(),
            "artifact.bin",
            "application/octet-stream",
            source,
        ))
        .unwrap()
    };
    let builder = ToolchainImageBuilder::new()
        .with_package(package("first", "first", "first", &first_source))
        .unwrap()
        .with_package(package("second", "second", "second", &second_source))
        .unwrap();
    let mut limits = ToolchainLimits::default();
    limits.package.max_resource_bytes = 4;
    limits.package.max_total_resource_bytes = 4;
    limits.max_total_image_resource_bytes = 6;
    let destination = temporary.path().join("image");

    assert!(matches!(
        builder.publish_create(&destination, limits),
        Err(ToolchainError::FileLimitExceeded { limit: 2, .. })
    ));
    assert!(!destination.exists());
}

#[test]
fn lock_limit_is_checked_before_publication_and_same_inputs_are_deterministic() {
    let temporary = tempfile::tempdir().unwrap();
    let too_small = temporary.path().join("too-small");
    let limits = ToolchainLimits {
        max_lock_bytes: 1,
        ..ToolchainLimits::default()
    };
    assert!(matches!(
        builder(bytes_recipe()).publish_create(&too_small, limits),
        Err(ToolchainError::LockBytesExceeded { limit: 1, .. })
    ));
    assert!(!too_small.exists());

    let first = builder(bytes_recipe())
        .publish_create(
            temporary.path().join("first-image"),
            ToolchainLimits::default(),
        )
        .unwrap();
    let second = builder(bytes_recipe())
        .publish_create(
            temporary.path().join("second-image"),
            ToolchainLimits::default(),
        )
        .unwrap();
    assert_eq!(first.lock(), second.lock());
}

#[test]
fn aggregate_manifest_budget_is_enforced_across_packages() {
    let manifest = |id: &str| {
        PackageManifest::new(
            PackageId::parse(format!("org.example.{id}@{VERSION}")).unwrap(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap()
    };
    let first = manifest("first-manifest");
    let second = manifest("second-manifest");
    let combined = write_manifest(&first).unwrap().len() + write_manifest(&second).unwrap().len();
    let builder = ToolchainImageBuilder::new()
        .with_package(PackageRecipe::from_manifest("first", first).unwrap())
        .unwrap()
        .with_package(PackageRecipe::from_manifest("second", second).unwrap())
        .unwrap();
    let limits = ToolchainLimits {
        max_total_image_manifest_bytes: u64::try_from(combined - 1).unwrap(),
        ..ToolchainLimits::default()
    };
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("image");

    assert!(matches!(
        builder.publish_create(&destination, limits),
        Err(ToolchainError::ImageManifestBytesExceeded { .. })
    ));
    assert!(!destination.exists());
}
