use rama::{
    error::ErrorContext as _,
    http::{
        HeaderName, HeaderValue,
        headers::{self, HeaderDecode, HeaderEncode, TypedHeader},
    },
    telemetry::tracing,
    utils::str::smol_str::ToSmolStr,
};

pub mod har;
pub mod malware;

macro_rules! impl_typed_usize_header {
    ($t:ident, $name:literal) => {
        #[derive(Debug, Clone)]
        pub struct $t(pub usize);

        impl TypedHeader for $t {
            fn name() -> &'static HeaderName {
                static NAME: HeaderName = HeaderName::from_static($name);
                &NAME
            }
        }

        impl HeaderEncode for $t {
            fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
                let s = self.0.to_smolstr();
                match HeaderValue::from_str(&s) {
                    Ok(v) => values.extend([v]),
                    Err(err) => {
                        tracing::error!(
                            "failed to encode usize '{}' as header value: {err}",
                            self.0
                        )
                    }
                }
            }
        }

        impl HeaderDecode for $t {
            fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
            where
                Self: Sized,
                I: Iterator<Item = &'i HeaderValue>,
            {
                let Some(value) = values.next() else {
                    tracing::trace!("{}: values missing", stringify!($t));
                    return Err(headers::Error::invalid());
                };

                match std::str::from_utf8(value.as_bytes())
                    .context("interpret bytes as utf-8 str")
                    .and_then(|s| s.parse().context("parse string as usize"))
                {
                    Ok(n) => {
                        if values.next().is_some() {
                            tracing::trace!("{}: only a single value is expected", stringify!($t));
                            return Err(headers::Error::invalid());
                        }
                        Ok(Self(n))
                    }
                    Err(err) => {
                        tracing::trace!("{}: invalid header value: {err}", stringify!($t));
                        return Err(headers::Error::invalid());
                    }
                }
            }
        }
    };
}

impl_typed_usize_header!(MockResponseRandomIndex, "x-mock-response-random-idx");
impl_typed_usize_header!(MockReplayIndex, "x-mock-replay-idx");
