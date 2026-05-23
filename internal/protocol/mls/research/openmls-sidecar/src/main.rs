use std::env;

const PROVIDER_NAME: &str = "openmls";
const IMPLEMENTATION: &str = "carbonstack-openmls-sidecar";
const MODE: &str = "experimental-sidecar";
const PHASE: &str = "phase2d-provider-info";

const WARNINGS: [&str; 4] = [
    "OpenMLS is not wired into CarbonStackComms",
    "Cypher does not route MLS payloads",
    "trust-state storage does not consume provider events",
    "no secret-bearing sidecar commands are implemented",
];

const UNSUPPORTED_COMMANDS: [&str; 9] = [
    "identity-create",
    "public-bundle-export",
    "conversation-create",
    "conversation-add-member",
    "conversation-join",
    "message-protect",
    "message-open",
    "state-checkpoint",
    "state-load-check",
];

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("provider-info") => print_provider_info(),
        Some("--help") | Some("-h") | None => print_help(),
        Some(other) => {
            print_unsupported_command(other);
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
    for command in UNSUPPORTED_COMMANDS {
        println!("  {command}");
    }
}

fn print_provider_info() {
    println!(
        r#"{{
  "ok": true,
  "command": "provider-info",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "data": {{
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
    "security_level": "experimental; not production E2EE"
  }},
  "events": [],
  "warnings": [
    "{warning0}",
    "{warning1}",
    "{warning2}",
    "{warning3}"
  ],
  "private_material_included": false
}}"#,
        provider = PROVIDER_NAME,
        implementation = IMPLEMENTATION,
        mode = MODE,
        phase = PHASE,
        warning0 = WARNINGS[0],
        warning1 = WARNINGS[1],
        warning2 = WARNINGS[2],
        warning3 = WARNINGS[3],
    );
}

fn print_unsupported_command(command: &str) {
    println!(
        r#"{{
  "ok": false,
  "command": "{command}",
  "provider": "{provider}",
  "implementation": "{implementation}",
  "mode": "{mode}",
  "phase": "{phase}",
  "error": {{
    "code": "unsupported_command",
    "message": "unsupported command: {command}",
    "provider_event": "provider.command.unsupported",
    "severity": "warning",
    "trust_relevant": false
  }},
  "events": [
    {{
      "event": "provider.command.unsupported",
      "severity": "warning",
      "trust_relevant": false
    }}
  ],
  "warnings": [],
  "private_material_included": false
}}"#,
        command = command,
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

    #[test]
    fn unsupported_commands_include_secret_bearing_commands() {
        assert!(UNSUPPORTED_COMMANDS.contains(&"identity-create"));
        assert!(UNSUPPORTED_COMMANDS.contains(&"message-protect"));
        assert!(UNSUPPORTED_COMMANDS.contains(&"message-open"));
        assert!(UNSUPPORTED_COMMANDS.contains(&"state-checkpoint"));
    }
}
