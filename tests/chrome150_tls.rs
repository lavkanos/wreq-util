//! Chrome 150+ signature algorithms and Chrome 152+ Trust Anchor IDs.

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
fn chrome150_adds_mldsa_before_classical_signature_algorithms() {
    let classical = tls_of(Profile::Chrome149).sigalgs_list.unwrap();
    let expected = format!("mldsa44:mldsa65:mldsa87:{classical}");
    for profile in [
        Emulation::Chrome150,
        Emulation::Chrome151,
        Emulation::Chrome152,
        Emulation::Chrome153,
    ] {
        let tls = tls_of(profile);
        assert_eq!(
            tls.sigalgs_list.as_deref(),
            Some(expected.as_str()),
            "{profile:?} signature algorithm order",
        );
    }
}

#[test]
fn earlier_profiles_do_not_request_anchors_or_signature_grease() {
    for profile in [
        Profile::Chrome149,
        Profile::Chrome150,
        Profile::Chrome151,
        Profile::Firefox151,
        Profile::Safari26_4,
    ] {
        let tls = tls_of(profile);
        assert!(tls.trust_anchors.is_none(), "{profile:?} trust anchors");
        assert_eq!(
            tls.grease_sigalgs_enabled, None,
            "{profile:?} signature GREASE"
        );
    }
}

#[test]
fn chrome152_anchors_follow_the_pki_feature() {
    #[cfg(feature = "emulation-chromium-pki")]
    let expected = chromium_roots::encoded_trust_anchor_ids();
    #[cfg(not(feature = "emulation-chromium-pki"))]
    let expected = [];
    #[cfg(feature = "emulation-chromium-pki")]
    assert!(!expected.is_empty());
    for profile in [Emulation::Chrome152, Emulation::Chrome153] {
        let tls = tls_of(profile);
        assert_eq!(tls.grease_sigalgs_enabled, Some(true));
        let request = tls
            .trust_anchors
            .expect("chrome 152+ sends the trust_anchors extension");
        assert_eq!(
            request.as_ref(),
            &expected,
            "{profile:?} must request the anchors paired with its root store",
        );
    }
}
