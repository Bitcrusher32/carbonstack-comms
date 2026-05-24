use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use std::fs::File;
use std::io;
use std::path::Path;

#[derive(Debug, Default)]
pub struct CarbonStackSidecarProvider {
    crypto: RustCrypto,
    key_store: MemoryStorage,
}

impl CarbonStackSidecarProvider {
    pub fn save_storage_to_path(&self, path: &Path) -> io::Result<()> {
        let output_file = File::create(path)?;
        self.key_store
            .save_to_file(&output_file)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }

    pub fn load_storage_from_path(&mut self, path: &Path) -> io::Result<()> {
        let input_file = File::open(path)?;
        self.key_store
            .load_from_file(&input_file)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }
}

impl OpenMlsProvider for CarbonStackSidecarProvider {
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
