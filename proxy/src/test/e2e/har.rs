use rama::{
    extensions::ExtensionsMut as _,
    http::{Request, layer::har::spec::Request as HarRequest},
    net::{Protocol, address::ProxyAddress},
};

use crate::test::e2e::runtime::Runtime;

pub fn parse_har_request(data: &str) -> Request {
    let har_req: HarRequest = serde_json::from_str(data).unwrap();
    har_req.try_into().unwrap()
}

pub fn parse_har_request_as_proxy_req(runtime: &Runtime, data: &str) -> Request {
    let mut req = parse_har_request(data);

    req.extensions_mut().insert(ProxyAddress {
        protocol: Some(Protocol::HTTP),
        address: runtime.proxy_addr().into(),
        credential: None,
    });

    req
}
