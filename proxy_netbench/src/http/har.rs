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

    const HAR_LOG_FILE_EXAMPLE: &str = r##"{"log":{"version":"1.2","creator":{"name":"WebInspector","version":"537.1"},"pages":[{"startedDateTime":"2012-08-28T05:14:24.803Z","id":"page_1","title":"http://www.igvita.com/","pageTimings":{"onContentLoad":299,"onLoad":301}}],"entries":[{"startedDateTime":"2012-08-28T05:14:24.803Z","time":121,"request":{"method":"GET","url":"http://www.igvita.com/","httpVersion":"HTTP/1.1","headers":[{"name":"Accept-Encoding","value":"gzip,deflate,sdch"},{"name":"Accept-Language","value":"en-US,en;q=0.8"},{"name":"Connection","value":"keep-alive"},{"name":"Accept-Charset","value":"ISO-8859-1,utf-8;q=0.7,*;q=0.3"},{"name":"Host","value":"www.igvita.com"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.82 Safari/537.1"},{"name":"Accept","value":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},{"name":"Cache-Control","value":"max-age=0"}],"queryString":[],"cookies":[],"headersSize":678,"bodySize":0},"response":{"status":200,"statusText":"OK","httpVersion":"HTTP/1.1","headers":[{"name":"Date","value":"Tue, 28 Aug 2012 05:14:24 GMT"},{"name":"Via","value":"HTTP/1.1 GWA"},{"name":"Transfer-Encoding","value":"chunked"},{"name":"Content-Encoding","value":"gzip"},{"name":"X-XSS-Protection","value":"1; mode=block"},{"name":"X-UA-Compatible","value":"IE=Edge,chrome=1"},{"name":"X-Page-Speed","value":"50_1_cn"},{"name":"Server","value":"nginx/1.0.11"},{"name":"Vary","value":"Accept-Encoding"},{"name":"Content-Type","value":"text/html; charset=utf-8"},{"name":"Cache-Control","value":"max-age=0, no-cache"},{"name":"Expires","value":"Tue, 28 Aug 2012 05:14:24 GMT"}],"cookies":[],"content":{"size":9521,"mimeType":"text/html","compression":5896},"redirectURL":"","headersSize":379,"bodySize":3625},"cache":{},"timings":{"blocked":0,"dns":-1,"connect":-1,"send":1,"wait":112,"receive":6,"ssl":-1},"pageref":"page_1"},{"startedDateTime":"2012-08-28T05:14:25.011Z","time":10,"request":{"method":"GET","url":"http://fonts.googleapis.com/css?family=Open+Sans:400,600","httpVersion":"HTTP/1.1","headers":[],"queryString":[{"name":"family","value":"Open+Sans:400,600"}],"cookies":[],"headersSize":71,"bodySize":0},"response":{"status":200,"statusText":"OK","httpVersion":"HTTP/1.1","headers":[],"cookies":[],"content":{"size":542,"mimeType":"text/css"},"redirectURL":"","headersSize":17,"bodySize":0},"cache":{},"timings":{"blocked":0,"dns":-1,"connect":-1,"send":-1,"wait":-1,"receive":2,"ssl":-1},"pageref":"page_1"},{"startedDateTime":"2012-08-28T05:14:25.017Z","time":31,"request":{"method":"GET","url":"http://1-ps.googleusercontent.com/h/www.igvita.com/css/style.css.pagespeed.ce.LzjUDNB25e.css","httpVersion":"HTTP/1.1","headers":[{"name":"Accept-Encoding","value":"gzip,deflate,sdch"},{"name":"Accept-Language","value":"en-US,en;q=0.8"},{"name":"Connection","value":"keep-alive"},{"name":"If-Modified-Since","value":"Mon, 27 Aug 2012 15:28:34 GMT"},{"name":"Accept-Charset","value":"ISO-8859-1,utf-8;q=0.7,*;q=0.3"},{"name":"Host","value":"1-ps.googleusercontent.com"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.82 Safari/537.1"},{"name":"Accept","value":"text/css,*/*;q=0.1"},{"name":"Cache-Control","value":"max-age=0"},{"name":"If-None-Match","value":"W/0"},{"name":"Referer","value":"http://www.igvita.com/"}],"queryString":[],"cookies":[],"headersSize":539,"bodySize":0},"response":{"status":304,"statusText":"Not Modified","httpVersion":"HTTP/1.1","headers":[{"name":"Date","value":"Mon, 27 Aug 2012 06:01:49 GMT"},{"name":"Age","value":"83556"},{"name":"Server","value":"GFE/2.0"},{"name":"ETag","value":"W/0"},{"name":"Expires","value":"Tue, 27 Aug 2013 06:01:49 GMT"}],"cookies":[],"content":{"size":14679,"mimeType":"text/css"},"redirectURL":"","headersSize":146,"bodySize":0},"cache":{},"timings":{"blocked":0,"dns":-1,"connect":-1,"send":1,"wait":24,"receive":2,"ssl":-1},"pageref":"page_1"},{"startedDateTime":"2012-08-28T05:14:25.021Z","time":30,"request":{"method":"GET","url":"http://1-ps.googleusercontent.com/h/www.igvita.com/js/libs/modernizr.84728.js.pagespeed.jm._DgXLhVY42.js","httpVersion":"HTTP/1.1","headers":[{"name":"Accept-Encoding","value":"gzip,deflate,sdch"},{"name":"Accept-Language","value":"en-US,en;q=0.8"},{"name":"Connection","value":"keep-alive"},{"name":"If-Modified-Since","value":"Sat, 25 Aug 2012 14:30:37 GMT"},{"name":"Accept-Charset","value":"ISO-8859-1,utf-8;q=0.7,*;q=0.3"},{"name":"Host","value":"1-ps.googleusercontent.com"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.82 Safari/537.1"},{"name":"Accept","value":"*/*"},{"name":"Cache-Control","value":"max-age=0"},{"name":"If-None-Match","value":"W/0"},{"name":"Referer","value":"http://www.igvita.com/"}],"queryString":[],"cookies":[],"headersSize":536,"bodySize":0},"response":{"status":304,"statusText":"Not Modified","httpVersion":"HTTP/1.1","headers":[{"name":"Date","value":"Sat, 25 Aug 2012 14:30:37 GMT"},{"name":"Age","value":"225828"},{"name":"Server","value":"GFE/2.0"},{"name":"ETag","value":"W/0"},{"name":"Expires","value":"Sun, 25 Aug 2013 14:30:37 GMT"}],"cookies":[],"content":{"size":11831,"mimeType":"text/javascript"},"redirectURL":"","headersSize":147,"bodySize":0},"cache":{},"timings":{"blocked":0,"dns":-1,"connect":0,"send":1,"wait":27,"receive":1,"ssl":-1},"pageref":"page_1"},{"startedDateTime":"2012-08-28T05:14:25.103Z","time":0,"request":{"method":"GET","url":"http://www.google-analytics.com/ga.js","httpVersion":"HTTP/1.1","headers":[],"queryString":[],"cookies":[],"headersSize":52,"bodySize":0},"response":{"status":200,"statusText":"OK","httpVersion":"HTTP/1.1","headers":[{"name":"Date","value":"Mon, 27 Aug 2012 21:57:00 GMT"},{"name":"Content-Encoding","value":"gzip"},{"name":"X-Content-Type-Options","value":"nosniff, nosniff"},{"name":"Age","value":"23052"},{"name":"Last-Modified","value":"Thu, 16 Aug 2012 07:05:05 GMT"},{"name":"Server","value":"GFE/2.0"},{"name":"Vary","value":"Accept-Encoding"},{"name":"Content-Type","value":"text/javascript"},{"name":"Expires","value":"Tue, 28 Aug 2012 09:57:00 GMT"},{"name":"Cache-Control","value":"max-age=43200, public"},{"name":"Content-Length","value":"14804"}],"cookies":[],"content":{"size":36893,"mimeType":"text/javascript"},"redirectURL":"","headersSize":17,"bodySize":0},"cache":{},"timings":{"blocked":0,"dns":-1,"connect":-1,"send":-1,"wait":-1,"receive":0,"ssl":-1},"pageref":"page_1"},{"startedDateTime":"2012-08-28T05:14:25.123Z","time":91,"request":{"method":"GET","url":"http://1-ps.googleusercontent.com/beacon?org=50_1_cn&ets=load:93&ifr=0&hft=32&url=http%3A%2F%2Fwww.igvita.com%2F","httpVersion":"HTTP/1.1","headers":[{"name":"Accept-Encoding","value":"gzip,deflate,sdch"},{"name":"Accept-Language","value":"en-US,en;q=0.8"},{"name":"Connection","value":"keep-alive"},{"name":"Accept-Charset","value":"ISO-8859-1,utf-8;q=0.7,*;q=0.3"},{"name":"Host","value":"1-ps.googleusercontent.com"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.82 Safari/537.1"},{"name":"Accept","value":"*/*"},{"name":"Referer","value":"http://www.igvita.com/"}],"queryString":[{"name":"org","value":"50_1_cn"},{"name":"ets","value":"load:93"},{"name":"ifr","value":"0"},{"name":"hft","value":"32"},{"name":"url","value":"http%3A%2F%2Fwww.igvita.com%2F"}],"cookies":[],"headersSize":448,"bodySize":0},"response":{"status":204,"statusText":"No Content","httpVersion":"HTTP/1.1","headers":[{"name":"Date","value":"Tue, 28 Aug 2012 05:14:25 GMT"},{"name":"Content-Length","value":"0"},{"name":"X-XSS-Protection","value":"1; mode=block"},{"name":"Server","value":"PagespeedRewriteProxy 0.1"},{"name":"Content-Type","value":"text/plain"},{"name":"Cache-Control","value":"no-cache"}],"cookies":[],"content":{"size":0,"mimeType":"text/plain","compression":0},"redirectURL":"","headersSize":202,"bodySize":0},"cache":{},"timings":{"blocked":0,"dns":-1,"connect":-1,"send":0,"wait":70,"receive":7,"ssl":-1},"pageref":"page_1"}]}}"##;
}
