use std::{fmt, str::FromStr, sync::Arc};

use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::{Request, Response, Uri},
    net::address::{Domain, DomainTrie},
    telemetry::tracing,
    utils::str::arcstr::{ArcStr, arcstr},
    utils::str::smol_str::StrExt,
};

use crate::{
    firewall::{
        events::{BlockedArtifact, BlockedEventInfo},
        malware_list::{PackageVersion, RemoteMalwareList},
        pac::PacScriptGenerator,
    },
    http::response::generate_generic_blocked_response_for_req,
    storage::SyncCompactDataStorage,
};

use super::{BlockedRequest, RequestAction, Rule};

mod malware_key;

pub(in crate::firewall) struct RuleChrome {
    target_domains: DomainTrie<()>,
    remote_malware_list: RemoteMalwareList,
}

impl RuleChrome {
    pub(in crate::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
    ) -> Result<Self, OpaqueError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError>,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/malware_chrome.json"),
            sync_storage,
            remote_malware_list_https_client,
            Some(Arc::new(malware_key::ChromeMalwareListEntryFormatter)),
        )
        .await
        .context("create remote malware list for chrome block rule")?;

        Ok(Self {
            target_domains: [
                "clients2.google.com",
                "update.googleapis.com",
                "clients2.googleusercontent.com",
            ]
            .into_iter()
            .map(|domain| (Domain::from_static(domain), ()))
            .collect(),
            remote_malware_list,
        })
    }
}

impl fmt::Debug for RuleChrome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleChrome").finish()
    }
}

impl Rule for RuleChrome {
    #[inline(always)]
    fn product_name(&self) -> &'static str {
        "Chrome Plugin"
    }

    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        self.target_domains.is_match_parent(domain)
    }

    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        for (domain, _) in self.target_domains.iter() {
            generator.write_domain(&domain);
        }
    }

    async fn evaluate_response(&self, resp: Response) -> Result<Response, OpaqueError> {
        Ok(resp)
    }

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, OpaqueError> {
        if !crate::http::try_get_domain_for_req(&req)
            .map(|domain| self.match_domain(&domain))
            .unwrap_or_default()
        {
            tracing::trace!("Chrome rule did not match incoming request: passthrough");
            return Ok(RequestAction::Allow(req));
        }

        if let Some((extension_id, version)) = Self::parse_crx_download_url(&req) {
            tracing::debug!(
                http.url.full = %req.uri(),
                http.request.method = %req.method(),
                "CRX download - extension id: {extension_id}, version: {:?}",
                version
            );

            if self.matches_malware_entry(extension_id.as_str(), &version) {
                tracing::info!(
                    http.url.full = %req.uri(),
                    http.request.method = %req.method(),
                    "blocked Chrome extension from CRX URL: {extension_id}, version: {:?}",
                    version
                );

                return Ok(RequestAction::Block(BlockedRequest {
                    response: generate_generic_blocked_response_for_req(req),
                    info: BlockedEventInfo {
                        artifact: BlockedArtifact {
                            product: arcstr!("chrome"),
                            identifier: extension_id,
                            version: Some(version),
                        },
                    },
                }));
            }
        }

        Ok(RequestAction::Allow(req))
    }
}

impl RuleChrome {
    fn matches_malware_entry(&self, extension_id: &str, version: &PackageVersion) -> bool {
        let normalized_id = extension_id.to_ascii_lowercase();
        let entries = self.remote_malware_list.find_entries(&normalized_id);
        let Some(entries) = entries.entries() else {
            return false;
        };

        entries
            .iter()
            .any(|e| Self::version_matches(&e.version, version))
    }

    fn version_matches(entry_version: &PackageVersion, observed_version: &PackageVersion) -> bool {
        if matches!(entry_version, PackageVersion::Any) {
            return true;
        }

        if entry_version == observed_version {
            return true;
        }

        // Chrome CRX URLs typically use 4-part versions (x.y.z.w), while the malware list
        // can contain 2-part (x.y) or 3-part (x.y.z / SemVer) versions.
        // To avoid false negatives, compare versions by padding the shorter one with
        // trailing ".0" segments up to 4 parts.
        fn normalize_to_4_parts(version: &str) -> [&str; 4] {
            let mut iter = version.split('.');
            [
                iter.next().unwrap_or("0"),
                iter.next().unwrap_or("0"),
                iter.next().unwrap_or("0"),
                iter.next().unwrap_or("0"),
            ]
        }

        fn equal_with_zero_padding(a: &str, b: &str) -> bool {
            if a == b {
                return true;
            }

            normalize_to_4_parts(a) == normalize_to_4_parts(b)
        }

        match (entry_version, observed_version) {
            (PackageVersion::Semver(v), PackageVersion::Unknown(raw)) => {
                equal_with_zero_padding(&v.to_string(), raw.as_str())
            }
            (PackageVersion::Unknown(raw), PackageVersion::Semver(v)) => {
                equal_with_zero_padding(raw.as_str(), &v.to_string())
            }
            (PackageVersion::Unknown(a), PackageVersion::Unknown(b)) => {
                equal_with_zero_padding(a.as_str(), b.as_str())
            }
            _ => false,
        }
    }

    fn parse_crx_download_url(req: &Request) -> Option<(ArcStr, PackageVersion)> {
        // Example CRX download URL path (after redirect):
        //   /crx/lajondecmobodlejlcjllhojikagldgd_1_2_3_4.crx
        let path = req.uri().path();

        let (_, filename) = path.rsplit_once('/')?;
        let base = filename.strip_suffix(".crx")?;

        let (extension_id, version_raw) = base.split_once('_')?;

        if extension_id.is_empty() || version_raw.is_empty() {
            return None;
        }

        let version_string = version_raw.replace_smolstr("_", ".");

        let version =
            PackageVersion::from_str(version_string.as_str()).unwrap_or(PackageVersion::None);

        Some((ArcStr::from(extension_id), version))
    }
}

#[cfg(test)]
mod test;
