use std::str::FromStr;

use rama::{
    http::Request, net::uri::util::percent_encoding, telemetry::tracing,
    utils::str::smol_str::StrExt,
};

use crate::package::version::PackageVersion;

pub(super) fn parse_crx_download_url(
    req: &Request,
) -> Option<(super::ChromePackageName, PackageVersion)> {
    if let Some(parsed) = parse_update2_crx_url(req) {
        return Some(parsed);
    }

    // Example CRX download URL path (after redirect):
    //   /crx/lajondecmobodlejlcjllhojikagldgd_1_2_3_4.crx
    let path = req.uri().path();

    let Some((_, filename)) = path.rsplit_once('/') else {
        tracing::debug!(
            http.url.path = path,
            "Chrome CRX parse failed: missing filename"
        );
        return None;
    };
    let Some(base) = filename.strip_suffix(".crx") else {
        tracing::debug!(
            http.url.path = path,
            http.url.filename = filename,
            "Chrome CRX parse failed: filename does not end in .crx"
        );
        return None;
    };

    let Some((extension_id, version_raw)) = base.split_once('_') else {
        tracing::debug!(
            http.url.path = path,
            http.url.filename = filename,
            "Chrome CRX parse failed: filename missing extension/version separator"
        );
        return None;
    };

    if extension_id.is_empty() || version_raw.is_empty() {
        tracing::debug!(
            http.url.path = path,
            chrome.extension_id = extension_id,
            chrome.version_raw = version_raw,
            "Chrome CRX parse failed: empty extension id or version"
        );
        return None;
    }

    let version_string = version_raw.replace_smolstr("_", ".");
    let Ok(version) = PackageVersion::from_str(version_string.as_str());

    Some((super::ChromePackageName::from(extension_id), version))
}

fn parse_update2_crx_url(req: &Request) -> Option<(super::ChromePackageName, PackageVersion)> {
    let uri = req.uri();
    if uri.path() != "/service/update2/crx" {
        return None;
    }

    let query = uri.query()?;
    let x_value = query_param(query, "x")?;
    let decoded_x = percent_decode(x_value);
    let extension_id = query_param(decoded_x.as_str(), "id")?;

    if extension_id.is_empty() {
        tracing::debug!(
            http.url.full = %uri,
            "Chrome update2/crx parse failed: missing extension id in x query parameter"
        );
        return None;
    }

    Some((
        super::ChromePackageName::from(extension_id),
        PackageVersion::None,
    ))
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then_some(v)
    })
}

fn percent_decode(input: &str) -> String {
    percent_encoding::percent_decode_str(input)
        .decode_utf8_lossy()
        .replace('+', " ")
}

#[cfg(test)]
#[path = "parser_test.rs"]
mod test;
