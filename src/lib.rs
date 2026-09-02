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
///
/// Prefer [`chrome_pki_client_builder`], which installs this store for you when
/// the profile sends populated anchors.
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

/// A [`wreq::ClientBuilder`] for Chrome that requests Chrome's real trust
/// anchors and verifies against Chrome's roots.
///
/// The presets always send an empty `trust_anchors` request. This helper is the
/// only place that populates it: for Chrome 150+ it swaps in Chrome's real
/// anchor IDs (from `chromium-root-certs`) and installs Chrome's roots via
/// [`chromium_root_store`], so the client can verify a chain anchored to one of
/// the IDs it asked for rather than fail the handshake because the default root
/// store cannot. The two travel together, so the builder this returns
/// never carries populated anchors without the matching roots. A caller that
/// chains its own [`wreq::ClientBuilder::tls_cert_store`] afterwards and drops
/// Chrome's roots is making that choice deliberately.
///
/// Chrome 149 and older, and non-Chrome profiles, send no `trust_anchors`
/// request, so the builder keeps the default cert store; no root swap happens for
/// them.
///
/// # Examples
///
/// ```no_run
/// use wreq_util::{chrome_pki_client_builder, Platform, Profile};
///
/// let client = chrome_pki_client_builder(Profile::Chrome152, Platform::Windows).build()?;
/// # Ok::<(), wreq::Error>(())
/// ```
#[cfg(feature = "emulation-chromium-pki")]
pub fn chrome_pki_client_builder(profile: Profile, platform: Platform) -> wreq::ClientBuilder {
    let emulation = chrome_pki_emulation(profile, platform);
    // Install Chrome's roots only when the emulation actually carries populated anchors (150+). For
    // 149 and non-Chrome the request is empty or absent, so the default roots verify the chain and
    // Chrome's store would just replace the system store for nothing.
    let carries_anchors = emulation
        .tls_options
        .as_ref()
        .and_then(|tls| tls.requested_trust_anchors.as_ref())
        .is_some_and(|ids| !ids.is_empty());
    let builder = wreq::Client::builder().emulation(emulation);
    if carries_anchors {
        builder.tls_cert_store(chromium_root_store())
    } else {
        builder
    }
}

// Build the emulation and replace the empty trust_anchors request (150+ only)
// with Chrome's real anchor IDs. Kept separate from the ClientBuilder so it can
// be inspected in tests.
#[cfg(feature = "emulation-chromium-pki")]
fn chrome_pki_emulation(profile: Profile, platform: Platform) -> wreq::Emulation {
    use wreq::IntoEmulation;
    let mut emulation = Emulation::builder()
        .profile(profile)
        .platform(platform)
        .build()
        .into_emulation();
    if let Some(tls) = emulation.tls_options.as_mut() {
        if tls.requested_trust_anchors.is_some() {
            tls.requested_trust_anchors =
                Some(chromium_root_certs::ENCODED_TRUST_ANCHOR_IDS.into());
        }
    }
    emulation
}

#[cfg(all(test, feature = "emulation-chromium-pki"))]
mod chrome_pki_tests {
    use super::{Platform, Profile, chrome_pki_emulation};

    fn request_len(profile: Profile) -> Option<usize> {
        chrome_pki_emulation(profile, Platform::Windows)
            .tls_options
            .expect("chrome profiles configure TLS options")
            .requested_trust_anchors
            .map(|ids| ids.len())
    }

    #[test]
    fn helper_populates_chromes_anchor_ids() {
        // Chrome's 28 anchor IDs encode to 184 bytes (from chromium-root-certs).
        for profile in [Profile::Chrome150, Profile::Chrome151, Profile::Chrome152] {
            assert_eq!(
                request_len(profile),
                Some(184),
                "{profile:?} carries anchor IDs",
            );
        }
    }

    #[test]
    fn helper_leaves_chrome149_untouched() {
        assert_eq!(request_len(Profile::Chrome149), None);
    }
}
