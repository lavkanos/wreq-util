//! Chrome 150+ sends the ML-DSA sigalgs and the trust_anchors extension.
//! Earlier versions don't, so check both.

#![cfg(all(not(target_arch = "wasm32"), feature = "emulation"))]

use wreq::IntoEmulation;
use wreq_util::{Emulation, Platform, Profile};

fn tls_of(profile: Profile) -> wreq::tls::TlsOptions {
    Emulation::builder()
        .profile(profile)
        .platform(Platform::Windows)
        .build()
        .into_emulation()
        .tls_options
        .expect("chrome profiles configure TLS options")
}

#[test]
fn chrome150_carries_trust_anchors_and_mldsa() {
    for profile in [
        Emulation::Chrome150,
        Emulation::Chrome151,
        Emulation::Chrome152,
    ] {
        let tls = tls_of(profile);
        assert!(
            tls.requested_trust_anchors.is_some(),
            "{profile:?} must send the trust_anchors extension",
        );
        assert!(
            tls.sigalgs_list
                .as_deref()
                .unwrap_or_default()
                .contains("mldsa"),
            "{profile:?} must advertise ML-DSA signature algorithms",
        );
    }
}

#[test]
fn chrome149_is_untouched() {
    let tls = tls_of(Emulation::Chrome149);
    assert!(
        tls.requested_trust_anchors.is_none(),
        "chrome149 must not send the trust_anchors extension",
    );
    assert!(
        !tls.sigalgs_list
            .as_deref()
            .unwrap_or_default()
            .contains("mldsa"),
        "chrome149 must not advertise ML-DSA",
    );
}

#[cfg(feature = "emulation-chromium-pki")]
#[test]
fn chrome150_sends_chromes_anchor_ids() {
    // Chrome's 28 anchor IDs encode to 184 bytes (from chromium-root-certs).
    for profile in [
        Emulation::Chrome150,
        Emulation::Chrome151,
        Emulation::Chrome152,
    ] {
        let tls = tls_of(profile);
        let ids = tls.requested_trust_anchors.expect("trust_anchors set");
        assert_eq!(ids.len(), 184, "{profile:?} sends Chrome's anchor IDs");
    }
}
