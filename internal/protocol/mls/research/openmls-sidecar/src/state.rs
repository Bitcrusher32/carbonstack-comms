use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const STATE_ROOT: &str = ".carbonstack-openmls-sidecar-state";
pub const DEV_SCOPE: &str = "dev";

pub fn device_state_dir(device_label: &str) -> PathBuf {
    Path::new(STATE_ROOT)
        .join(DEV_SCOPE)
        .join("devices")
        .join(device_label)
}

pub fn identity_prep_manifest_path(device_label: &str) -> PathBuf {
    device_state_dir(device_label).join("identity-prep.json")
}

pub fn write_identity_prep_manifest(device_label: &str) -> io::Result<PathBuf> {
    let dir = device_state_dir(device_label);
    let manifest_path = identity_prep_manifest_path(device_label);

    if manifest_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "identity prep manifest already exists",
        ));
    }

    fs::create_dir_all(&dir)?;

    let manifest = format!(
        concat!(
            "{{\n",
            "  \"manifest_version\": \"identity-prep/v0\",\n",
            "  \"device_label\": \"{}\",\n",
            "  \"state_scope\": \"dev-local-sidecar-state\",\n",
            "  \"identity_created\": false,\n",
            "  \"provider_storage_written\": false,\n",
            "  \"private_material_included\": false,\n",
            "  \"warning\": \"prep manifest only; no OpenMLS identity material generated\"\n",
            "}}\n"
        ),
        json_escape(device_label)
    );

    fs::write(&manifest_path, manifest)?;

    Ok(manifest_path)
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
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
}
