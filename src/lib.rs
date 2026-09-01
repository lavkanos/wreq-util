#![deny(unused)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, deny(warnings))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![doc = include_str!("../README.md")]

#[cfg(feature = "emulation")]
pub mod emulate;
mod rand;
pub mod tower;

#[cfg(feature = "emulation")]
pub use self::emulate::{Emulation, Platform, Profile};

/// Chrome's root store from chromium-root-certs, for
/// [`wreq::ClientBuilder::tls_cert_store`]. Needed with emulation-chromium-pki:
/// Chrome 150+ requests specific trust_anchors and a server may return a chain
/// anchored to one of them, so the client needs Chrome's roots to verify it.
/// Built once; the returned store is cheap to clone.
#[cfg(feature = "emulation-chromium-pki")]
pub fn chromium_root_store() -> wreq::tls::trust::CertStore {
    use std::sync::LazyLock;
    static STORE: LazyLock<wreq::tls::trust::CertStore> = LazyLock::new(|| {
        wreq::tls::trust::CertStore::from_der_certs(
            chromium_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(AsRef::as_ref),
        )
        .expect("chromium-root-certs ships valid DER roots")
    });
    STORE.clone()
}
