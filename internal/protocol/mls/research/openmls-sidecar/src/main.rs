use std::env;

const PROVIDER_NAME: &str = "openmls";
const IMPLEMENTATION: &str = "carbonstack-openmls-sidecar";
const MODE: &str = "experimental-sidecar";
const PHASE: &str = "phase2d-provider-info";

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("provider-info") => print_provider_info(),
        Some("--help") | Some("-h") | None => print_help(),
        Some(other) => {
            eprintln!("unsupported command: {other}");
            eprintln!("run: cargo run -- provider-info");
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!("CarbonStack OpenMLS sidecar");
    println!("Status: experimental Phase 2D provider boundary prototype");
    println!();
    println!("Supported commands:");
    println!("  provider-info");
    println!();
    println!("Unsupported intentionally:");
    println!("  identity-create");
    println!("  public-bundle-export");
    println!("  conversation-create");
    println!("  conversation-add-member");
    println!("  conversation-join");
    println!("  message-protect");
    println!("  message-open");
    println!("  state-checkpoint");
    println!("  state-load-check");
}

fn print_provider_info() {
    println!(
        r#"{{
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "capabilities": [
    "provider-info"
  ],
  "unsupported": [
    "identity-create",
    "public-bundle-export",
    "conversation-create",
    "conversation-add-member",
    "conversation-join",
    "message-protect",
    "message-open",
    "state-checkpoint",
    "state-load-check"
  ],
  "security_level": "experimental; not production E2EE",
  "private_material_included": false,
  "warnings": [
    "OpenMLS is not wired into CarbonStackComms",
    "Cypher does not route MLS payloads",
    "trust-state storage does not consume provider events",
    "no secret-bearing sidecar commands are implemented"
  ]
}}"#,
        provider = PROVIDER_NAME,
        implementation = IMPLEMENTATION,
        mode = MODE,
        phase = PHASE,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_info_constants_are_phase2d_bootstrap() {
        assert_eq!(PROVIDER_NAME, "openmls");
        assert_eq!(IMPLEMENTATION, "carbonstack-openmls-sidecar");
        assert_eq!(MODE, "experimental-sidecar");
        assert_eq!(PHASE, "phase2d-provider-info");
    }
}
