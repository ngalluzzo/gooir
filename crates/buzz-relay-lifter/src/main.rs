use std::{env, fs, process};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let ingest_path = arguments.next().ok_or_else(usage)?;
    let kind_path = arguments.next().ok_or_else(usage)?;
    let push_lease_path = arguments.next().ok_or_else(usage)?;
    let protocol_lift_path = arguments.next().ok_or_else(usage)?;
    let artifact = arguments.next().ok_or_else(usage)?;
    let push_lease_artifact = arguments.next().ok_or_else(usage)?;
    let authority = arguments.next().ok_or_else(usage)?;
    let revision = arguments.next().ok_or_else(usage)?;
    if arguments.next().is_some() {
        return Err(usage());
    }

    let ingest_source = fs::read_to_string(&ingest_path)
        .map_err(|error| format!("failed to read {ingest_path}: {error}"))?;
    let kind_source = fs::read_to_string(&kind_path)
        .map_err(|error| format!("failed to read {kind_path}: {error}"))?;
    let push_lease_source = fs::read_to_string(&push_lease_path)
        .map_err(|error| format!("failed to read {push_lease_path}: {error}"))?;
    let protocol_lift: buzz_protocol_lifter::ProtocolLift = serde_json::from_slice(
        &fs::read(&protocol_lift_path)
            .map_err(|error| format!("failed to read {protocol_lift_path}: {error}"))?,
    )
    .map_err(|error| format!("failed to parse {protocol_lift_path}: {error}"))?;

    let lift = buzz_relay_lifter::lift_relay_ingest(
        buzz_relay_lifter::RelaySourceInputs::new(&ingest_source, &kind_source, &push_lease_source),
        &protocol_lift,
        authority,
        artifact,
        push_lease_artifact,
        revision,
    )
    .map_err(|error| format!("failed to lift {ingest_path}: {error}"))?;
    let output = serde_json::to_string_pretty(&lift)
        .map_err(|error| format!("failed to serialize lift: {error}"))?;
    println!("{output}");
    Ok(())
}

fn usage() -> String {
    "usage: buzz-relay-lifter <ingest-source> <kind-source> <push-lease-source> <protocol-lift-json> <artifact-id> <push-lease-artifact-id> <authority> <revision>".to_owned()
}
