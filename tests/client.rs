#![cfg(not(target_arch = "wasm32"))]
mod support;

use support::server;
use wreq::Client;
use wreq_util::{Emulation, Platform};

#[tokio::test]
async fn test_client_emulation_device() {
    let server = server::http(move |req| async move {
        for (name, value) in req.headers() {
            if name == "user-agent" {
                assert_eq!(
                    value,
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
                );
            }
            if name == "sec-ch-ua" {
                assert_eq!(
                    value,
                    r#""Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133""#
                );
            }
            if name == "sec-ch-ua-mobile" {
                assert_eq!(value, "?0");
            }
            if name == "sec-ch-ua-platform" {
                assert_eq!(value, "\"Linux\"");
            }
        }
        http::Response::default()
    });

    let url = format!("http://{}/ua", server.addr());
    let res = Client::builder()
        .emulation(
            Emulation::builder()
                .profile(Emulation::Chrome133)
                .platform(Platform::Linux)
                .http2(true)
                .build(),
        )
        .build()
        .expect("Unable to build client")
        .get(&url)
        .send()
        .await
        .expect("request");

    assert_eq!(res.status(), wreq::StatusCode::OK);
}

async fn assert_chrome152_headers(
    platform: Platform,
    expected_platform: &'static str,
    expected_user_agent: &'static str,
) {
    let server = server::http(move |req| async move {
        assert_eq!(
            req.headers().get("sec-ch-ua").unwrap(),
            r#""Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152""#
        );
        assert_eq!(
            req.headers().get("sec-ch-ua-platform").unwrap(),
            expected_platform
        );
        assert_eq!(
            req.headers().get("user-agent").unwrap(),
            expected_user_agent
        );
        http::Response::default()
    });

    let url = format!("http://{}/ua", server.addr());
    let res = Client::builder()
        .emulation(
            Emulation::builder()
                .profile(Emulation::Chrome152)
                .platform(platform)
                .build(),
        )
        .build()
        .expect("Unable to build client")
        .get(&url)
        .send()
        .await
        .expect("request");

    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn test_chrome152_windows_and_macos_headers() {
    assert_chrome152_headers(
        Platform::Windows,
        "\"Windows\"",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
    )
    .await;
    assert_chrome152_headers(
        Platform::MacOS,
        "\"macOS\"",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
    )
    .await;
}
