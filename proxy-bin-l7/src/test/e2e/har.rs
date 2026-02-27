use rama::http::{Request, layer::har::spec::Request as HarRequest};

pub fn parse_har_request(data: &str) -> Request {
    let har_req: HarRequest = serde_json::from_str(data).unwrap();
    har_req.try_into().unwrap()
}
