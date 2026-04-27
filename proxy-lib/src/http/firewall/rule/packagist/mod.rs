use std::fmt;

use rama::{
    Service,
    error::{BoxError, ErrorContext as _, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{
        Body, Request, Response, Uri,
        body::util::BodyExt as _,
        headers::{ContentType, HeaderMapExt as _},
    },
    net::address::Domain,
    telemetry::tracing,
    utils::{str::arcstr::ArcStr, time::now_unix_ms},
};
use serde_json::Value;

use crate::{
    endpoint_protection::{PackagePolicyDecision, PolicyEvaluator, RemoteEndpointConfig},
    http::{
        KnownContentType,
        firewall::{
            domain_matcher::DomainMatcher,
            events::{Artifact, BlockReason, BlockedEvent, MinPackageAgeEvent},
            notifier::EventNotifier,
        },
    },
    package::{
        malware_list::{LowerCaseEntryFormatter, RemoteMalwareList},
        released_packages_list::{LowerCaseReleasedPackageFormatter, RemoteReleasedPackagesList},
        version::PackageVersion,
    },
    storage::SyncCompactDataStorage,
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

use super::{HttpRequestMatcherView, Rule, make_response_uncacheable};

mod json;
mod path;

pub(in crate::http::firewall) struct RulePackagist {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
    remote_released_packages_list: RemoteReleasedPackagesList,
    remote_endpoint_config: Option<RemoteEndpointConfig>,
    policy_evaluator: Option<PolicyEvaluator>,
    notifier: Option<EventNotifier>,
}

impl RulePackagist {
    pub(in crate::http::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
        policy_evaluator: Option<PolicyEvaluator>,
        notifier: Option<EventNotifier>,
        remote_endpoint_config: Option<RemoteEndpointConfig>,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError> + Clone,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/malware_packagist.json"),
            sync_storage.clone(),
            remote_malware_list_https_client.clone(),
            LowerCaseEntryFormatter,
        )
        .await
        .context("create remote malware list for packagist block rule")?;

        let remote_released_packages_list = RemoteReleasedPackagesList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/releases/packagist.json"),
            sync_storage,
            remote_malware_list_https_client,
            LowerCaseReleasedPackageFormatter,
        )
        .await
        .context("create remote released packages list for packagist block rule")?;

        Ok(Self {
            target_domains: ["repo.packagist.org"].into_iter().collect(),
            remote_malware_list,
            remote_released_packages_list,
            remote_endpoint_config,
            policy_evaluator,
            notifier,
        })
    }

    const DEFAULT_MIN_PACKAGE_AGE_SECS: i64 = 48 * 3600;

    fn get_package_age_cutoff_secs(&self) -> i64 {
        let maybe_ts = self.remote_endpoint_config.as_ref().and_then(|c| {
            c.get_ecosystem_config("packagist")
                .config()
                .and_then(|cfg| cfg.minimum_allowed_age_timestamp)
        });
        if let Some(ts_secs) = maybe_ts {
            return ts_secs;
        }
        (now_unix_ms() / 1000) - Self::DEFAULT_MIN_PACKAGE_AGE_SECS
    }

    fn is_version_malware(&self, package: &str, version: &PackageVersion) -> bool {
        self.remote_malware_list
            .has_entries_with_version(package, version.clone())
    }
}

impl fmt::Debug for RulePackagist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RulePackagist").finish()
    }
}

impl Rule for RulePackagist {
    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        self.target_domains.is_match(domain)
    }

    #[cfg(feature = "pac")]
    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        for domain in self.target_domains.iter() {
            generator.write_domain(&domain);
        }
    }

    #[inline(always)]
    fn match_http_response_payload_inspection_request(
        &self,
        req: HttpRequestMatcherView<'_>,
    ) -> bool {
        path::parse_package_name_from_path(req.uri.path()).is_some()
    }

    async fn evaluate_response(&self, resp: Response, req_uri: &Uri) -> Result<Response, BoxError> {
        let Some(package_name) = path::parse_package_name_from_path(req_uri.path()) else {
            return Ok(resp);
        };

        let Some(KnownContentType::Json) = resp
            .headers()
            .typed_get::<ContentType>()
            .and_then(KnownContentType::detect_from_content_type_header)
        else {
            return Ok(resp);
        };

        let cutoff_secs = self.get_package_age_cutoff_secs();
        let (mut parts, body) = resp.into_parts();

        let bytes = body
            .collect()
            .await
            .context("collect packagist metadata response body")?
            .to_bytes();

        let Some((package_key, entries)) = json::parse_and_deminify(&bytes, &package_name) else {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        };

        if let Some(evaluator) = self.policy_evaluator.as_ref()
            && matches!(
                evaluator.evaluate_package_install("packagist", &package_name),
                PackagePolicyDecision::Allow
            )
        {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        }

        let mut suppressed_malware: Vec<PackageVersion> = Vec::new();
        let mut suppressed_min_age: Vec<PackageVersion> = Vec::new();
        let mut kept: Vec<Value> = Vec::new();

        for entry in &entries {
            let Some(version) = json::version_from_entry(entry) else {
                kept.push(Value::Object(entry.clone()));
                continue;
            };

            if self.is_version_malware(&package_name, &version) {
                tracing::info!(
                    package = %package_name,
                    version = %version,
                    "packagist: suppressing malware version from metadata response"
                );
                if let Some(notifier) = &self.notifier {
                    notifier
                        .notify_blocked(BlockedEvent {
                            ts_ms: now_unix_ms(),
                            artifact: Artifact {
                                product: "packagist".into(),
                                identifier: ArcStr::from(package_name.as_str()),
                                display_name: Some(ArcStr::from(package_name.as_str())),
                                version: Some(version.clone()),
                            },
                            block_reason: BlockReason::Malware,
                        })
                        .await;
                }
                suppressed_malware.push(version);
                continue;
            }

            let is_recent = json::time_from_entry(entry).is_some_and(|t| t > cutoff_secs)
                || self.remote_released_packages_list.is_recently_released(
                    &package_name,
                    Some(&version),
                    cutoff_secs,
                );

            if is_recent {
                tracing::info!(
                    package = %package_name,
                    version = %version,
                    "packagist: suppressing too-new version from metadata response"
                );
                suppressed_min_age.push(version);
                continue;
            }

            kept.push(Value::Object(entry.clone()));
        }

        if suppressed_malware.is_empty() && suppressed_min_age.is_empty() {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        }

        let Some(new_bytes) = json::serialize(package_key, kept) else {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        };

        tracing::info!(
            package = %package_name,
            suppressed_malware = ?suppressed_malware,
            suppressed_min_age = ?suppressed_min_age,
            "packagist metadata rewritten: suppressed versions"
        );

        make_response_uncacheable(&mut parts.headers);

        if !suppressed_min_age.is_empty()
            && let Some(notifier) = &self.notifier
        {
            let event = MinPackageAgeEvent {
                ts_ms: now_unix_ms(),
                artifact: Artifact {
                    product: "packagist".into(),
                    identifier: ArcStr::from(package_name.as_str()),
                    display_name: Some(ArcStr::from(package_name.as_str())),
                    version: None,
                },
                suppressed_versions: suppressed_min_age,
            };
            notifier.notify_min_package_age(event).await;
        }

        Ok(Response::from_parts(parts, Body::from(new_bytes)))
    }
}
