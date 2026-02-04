use std::{fs::File, path::PathBuf};

use rama::{
    bytes::Bytes,
    error::{ErrorContext as _, OpaqueError},
    http::{Body, Request, Response, body::util::BodyExt, layer::har, request, response},
};

#[derive(Debug)]
pub struct HarEntry {
    pub request: HarRequest,
    pub response: Option<HarResponse>,
    pub start_offset: u64,
}

#[derive(Debug)]
pub struct HarRequest {
    pub parts: request::Parts,
    pub payload: Option<Bytes>,
}

impl HarRequest {
    pub fn clone_as_http_request(&self) -> Request {
        Request::from_parts(
            self.parts.clone(),
            match self.payload.as_ref() {
                Some(bytes) => Body::from(bytes.clone()),
                None => Body::empty(),
            },
        )
    }
}

#[derive(Debug)]
pub struct HarResponse {
    pub parts: response::Parts,
    pub payload: Option<Bytes>,
}

impl HarResponse {
    pub fn clone_as_http_response(&self) -> Response {
        Response::from_parts(
            self.parts.clone(),
            match self.payload.as_ref() {
                Some(bytes) => Body::from(bytes.clone()),
                None => Body::empty(),
            },
        )
    }
}

pub async fn load_har_entries(path: PathBuf) -> Result<Vec<HarEntry>, OpaqueError> {
    let log_file: har::spec::LogFile = tokio::task::spawn_blocking(move || {
        let file = File::open(path).context("open har file")?;
        serde_json::from_reader(file).context("json decode har (log) file")
    })
    .await
    .context("await blocking json decode task")?
    .context("read and decode har file")?;
    har_log_file_as_har_entry_vec(log_file).await
}

async fn har_log_file_as_har_entry_vec(
    log_file: har::spec::LogFile,
) -> Result<Vec<HarEntry>, OpaqueError> {
    if log_file.log.entries.is_empty() {
        return Err(OpaqueError::from_display(
            "empty har log file (contains no entries)",
        ));
    }

    let mut har_entries = Vec::with_capacity(log_file.log.entries.len());
    let min_start_date = log_file
        .log
        .entries
        .iter()
        .map(|entry| entry.started_date_time.timestamp_micros())
        .min()
        .context("get min start date for all entries in har log")?
        .max(0);

    for entry in log_file.log.entries {
        let (parts, body) = Request::try_from(entry.request)
            .context("convert har request to http request")?
            .into_parts();
        let payload = body.collect().await.context("collect req bod")?.to_bytes();
        let har_request = HarRequest {
            parts,
            payload: payload.is_empty().then_some(payload),
        };

        let har_response = match entry.response {
            Some(response) => {
                let (parts, body) = Response::try_from(response)
                    .context("convert har response to http response")?
                    .into_parts();
                let payload = body.collect().await.context("collect req bod")?.to_bytes();
                Some(HarResponse {
                    parts,
                    payload: payload.is_empty().then_some(payload),
                })
            }
            None => None,
        };

        har_entries.push(HarEntry {
            request: har_request,
            response: har_response,
            start_offset: (entry.started_date_time.timestamp_micros() - min_start_date) as u64,
        })
    }

    har_entries.sort_by_key(|entry| entry.start_offset);

    Ok(har_entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_load_har_entries() {
        let log_file = serde_json::from_str(HAR_LOG_FILE_EXAMPLE).unwrap();
        let har_entries = har_log_file_as_har_entry_vec(log_file).await.unwrap();

        assert_eq!(6, har_entries.len());

        assert_eq!(0, har_entries[0].start_offset);
        assert_eq!(320000, har_entries.last().unwrap().start_offset);

        assert_eq!(
            "http://www.igvita.com/",
            har_entries[0].request.parts.uri.to_string()
        );
    }

    #[tokio::test]
    async fn test_load_har_entries_from_synthetic_file() {
        let log_file = serde_json::from_str(HAR_LOG_FILE_SYNETHETIC_EXAMPLE).unwrap();
        let har_entries = har_log_file_as_har_entry_vec(log_file).await.unwrap();

        assert_eq!(240, har_entries.len());
    }

    const HAR_LOG_FILE_EXAMPLE: &str = include_str!("../../har_files/mini_toy.har.json");
    const HAR_LOG_FILE_SYNETHETIC_EXAMPLE: &str =
        include_str!("../../har_files/synthetic.har.json");
}
