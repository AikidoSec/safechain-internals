use std::borrow::Cow;

use rama::{
    extensions::{Extension, ExtensionsRef},
    http::{HeaderMap, Request, Uri, utils::request_uri},
    net::{address::Domain, http::RequestContext, proxy::ProxyTarget},
};

macro_rules! request_meta_type {
    ($name:ident, $t:ty) => {
        #[derive(Debug)]
        /// meta information that can be stored as extension data in a request,
        /// such that it is also available for later use while processing
        /// its response.
        pub struct $name(pub $t);

        impl Extension for $name {}
    };
}

request_meta_type!(RequestMetaUri, Uri);

impl RequestMetaUri {
    #[inline(always)]
    pub fn from_request<Body>(req: &Request<Body>) -> Self {
        Self(request_uri(req).into_owned())
    }
}

request_meta_type!(RequestMetaHeaders, HeaderMap);

impl RequestMetaHeaders {
    #[inline(always)]
    pub fn from_request<Body>(req: &Request<Body>) -> Self {
        Self(req.headers().clone())
    }
}

pub fn try_get_domain_for_req<Body>(req: &Request<Body>) -> Option<Cow<'_, Domain>> {
    if let Some(ProxyTarget(target)) = req.extensions().get_ref()
        && let Some(domain) = target.host.as_domain()
    {
        Some(Cow::Borrowed(domain))
    } else {
        RequestContext::try_from(req)
            .ok()
            .map(|ctx| ctx.host_with_port())
            .and_then(|v| v.host.into_domain())
            .map(Cow::Owned)
    }
}

#[cfg(test)]
#[path = "req_info_tests.rs"]
mod tests;
