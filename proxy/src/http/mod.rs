pub mod response;

mod content_type;
pub use content_type::RequestedContentType;

mod req_info;
pub use req_info::try_get_domain_for_req;
