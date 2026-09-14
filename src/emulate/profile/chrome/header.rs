use super::*;

pub fn header_initializer(
    sec_ch_ua: &'static str,
    ua: &'static str,
    emulation_os: Platform,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    header_chrome_sec_ch_ua!(
        headers,
        sec_ch_ua,
        emulation_os.platform(),
        emulation_os.is_mobile()
    );
    headers.insert(
        HeaderName::from_static("upgrade-insecure-requests"),
        HeaderValue::from_static("1"),
    );
    header_chrome_ua!(headers, ua);
    header_chrome_accept!(headers);
    header_chrome_sec_fetch!(headers);
    header_chrome_accept_encoding!(headers);
    headers
}

pub fn header_initializer_with_zstd(
    sec_ch_ua: &'static str,
    ua: &'static str,
    emulation_os: Platform,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    header_chrome_sec_ch_ua!(
        headers,
        sec_ch_ua,
        emulation_os.platform(),
        emulation_os.is_mobile()
    );
    headers.insert(
        HeaderName::from_static("upgrade-insecure-requests"),
        HeaderValue::from_static("1"),
    );
    header_chrome_ua!(headers, ua);
    header_chrome_accept!(headers);
    header_chrome_sec_fetch!(headers);
    header_chrome_accept_encoding!(zstd, headers);
    headers
}

pub fn header_initializer_with_zstd_priority(
    sec_ch_ua: &'static str,
    ua: &'static str,
    emulation_os: Platform,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    header_chrome_sec_ch_ua!(
        headers,
        sec_ch_ua,
        emulation_os.platform(),
        emulation_os.is_mobile()
    );
    headers.insert(
        HeaderName::from_static("upgrade-insecure-requests"),
        HeaderValue::from_static("1"),
    );
    header_chrome_ua!(headers, ua);
    header_chrome_accept!(headers);
    header_chrome_sec_fetch!(headers);
    header_chrome_accept_encoding!(zstd, headers);
    headers.insert(
        HeaderName::from_static("priority"),
        HeaderValue::from_static("u=0, i"),
    );
    headers
}

/// Header order for Chrome 150 and newer.
///
/// Chrome 150 moved `accept-language` from just after `accept-encoding` to just
/// after the `sec-ch-ua` block, which shifts it from position 12 to position 4.
/// Measured over HTTP/2 against real binaries (Chrome 149.0.7827.155 and
/// Chrome for Testing 150.0.7828.0 / 151.0.7872.0 / 152.0.7923.0):
///
/// ```text
/// 149  sec-ch-ua … upgrade-insecure-requests … accept-encoding accept-language priority
/// 150+ sec-ch-ua … accept-language upgrade-insecure-requests … accept-encoding priority
/// ```
///
/// Profiles up to 149 keep [`header_initializer_with_zstd_priority`].
pub fn header_initializer_with_zstd_priority_v150(
    sec_ch_ua: &'static str,
    ua: &'static str,
    emulation_os: Platform,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    header_chrome_sec_ch_ua!(
        headers,
        sec_ch_ua,
        emulation_os.platform(),
        emulation_os.is_mobile()
    );
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert(
        HeaderName::from_static("upgrade-insecure-requests"),
        HeaderValue::from_static("1"),
    );
    header_chrome_ua!(headers, ua);
    header_chrome_accept!(headers);
    header_chrome_sec_fetch!(headers);
    header_chrome_accept_encoding!(zstd_only, headers);
    headers.insert(
        HeaderName::from_static("priority"),
        HeaderValue::from_static("u=0, i"),
    );
    headers
}
