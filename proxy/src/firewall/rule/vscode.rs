use std::fmt;

use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::{Request, Response, Uri},
    net::address::{Domain, DomainTrie},
    telemetry::tracing,
    utils::str::{smol_str::format_smolstr, starts_with_ignore_ascii_case},
};

use crate::{
    firewall::{malware_list::RemoteMalwareList, pac::PacScriptGenerator},
    http::response::generate_generic_blocked_response_for_req,
    storage::SyncCompactDataStorage,
};

use super::{RequestAction, Rule};

pub(in crate::firewall) struct RuleVSCode {
    target_domains: DomainTrie<()>,
    remote_malware_list: RemoteMalwareList,
}

impl RuleVSCode {
    pub(in crate::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
    ) -> Result<Self, OpaqueError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError>,
    {
        // NOTE: should you ever need to share a remote malware list between different rules,
        // you would simply create it outside of the rule, clone and pass it in.
        // These remoter malware list resources are cloneable and will share the list,
        // so it only gets updated once
        let remote_malware_list = RemoteMalwareList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/malware_vscode.json"),
            sync_storage,
            remote_malware_list_https_client,
        )
        .await
        .context("create remote malware list for vscode block rule")?;

        Ok(Self {
            // NOTE: should you ever make this list dynamic we would stop hardcoding these target domains here...
            target_domains: ["gallery.vsassets.io", "gallerycdn.vsassets.io"]
                .into_iter()
                .map(|domain| (Domain::from_static(domain), ()))
                .collect(),
            remote_malware_list,
        })
    }
}

impl fmt::Debug for RuleVSCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleVSCode").finish()
    }
}

impl Rule for RuleVSCode {
    #[inline(always)]
    fn product_name(&self) -> &'static str {
        "VSCode"
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

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, OpaqueError> {
        if !crate::http::try_get_domain_for_req(&req)
            .map(|domain| self.match_domain(&domain))
            .unwrap_or_default()
        {
            tracing::trace!("VSCode rule did not match incoming request: passthrough");
            return Ok(RequestAction::Allow(req));
        }

        let path = req.uri().path().trim_start_matches('/');
        if !starts_with_ignore_ascii_case(path, "extensions/") {
            tracing::debug!("VSCode url: path no match: {path}; passthrough");
            return Ok(RequestAction::Allow(req));
        }

        let mut path_iter = path.split('/').skip(1); // skip extensions

        let Some(publisher_name) = path_iter.next() else {
            tracing::debug!(
                "VSCode url: publisher name not found in uri path: {path}; passthrough"
            );
            return Ok(RequestAction::Allow(req));
        };
        let Some(package_name) = path_iter.next() else {
            tracing::debug!(
                "VSCode url: publisher name not found in uri path: {path}; passthrough"
            );
            return Ok(RequestAction::Allow(req));
        };

        // format defined by remote malware list,
        // e.g. klustfix.kluster-code-verify
        // NOTE: do we not need to worry about casing???
        let fq_package_name = format_smolstr!("{}.{}", publisher_name.trim(), package_name.trim());

        if let Some(_entries) = self
            .remote_malware_list
            .find_entries(&fq_package_name)
            .entries()
        {
            // NOTE: if we only want to block specific version ranges we would need
            // to go through the found package entries and compare that with the
            // version requested in the request :)

            tracing::debug!("blocked VSCode plugin: {fq_package_name}");
            return Ok(RequestAction::Block(
                generate_generic_blocked_response_for_req(req),
            ));
        }

        tracing::debug!("VSCode url: plugin {fq_package_name}: not blocked; let it go...");
        Ok(RequestAction::Allow(req))
    }

    async fn evaluate_response(&self, resp: Response) -> Result<Response, OpaqueError> {
        // Pass through for now - response modification can be added in future PR
        Ok(resp)
    }
}
