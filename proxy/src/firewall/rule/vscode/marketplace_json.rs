use memchr::memmem;
use rama::bytes::Bytes;
use rama::telemetry::tracing;
use rama::utils::str::smol_str::{SmolStr, format_smolstr};
use sonic_rs::{JsonContainerTrait, JsonValueMutTrait, JsonValueTrait, Value};

use super::RuleVSCode;

const MAX_MARKETPLACE_JSON_TRAVERSAL_DEPTH: usize = 32;

impl RuleVSCode {
    /// Attempts to parse a VS Code Marketplace JSON response body and rewrites it in-place
    /// to mark extensions as malware when they match the malware list.
    pub(super) fn rewrite_marketplace_json_response_body(
        &self,
        body_bytes: &[u8],
    ) -> Option<Bytes> {
        memmem::find(body_bytes, br#""displayName""#)?;

        if memmem::find(body_bytes, br#""publisherName""#).is_none()
            && memmem::find(body_bytes, br#""publisher""#).is_none()
        {
            return None;
        }

        if memmem::find(body_bytes, br#""extensionName""#).is_none()
            && memmem::find(body_bytes, br#""name""#).is_none()
        {
            return None;
        }

        let mut value: Value = match sonic_rs::from_slice(body_bytes) {
            Ok(val) => val,
            Err(err) => {
                tracing::trace!(error = %err, "VSCode response: failed to parse JSON; passthrough");
                return None;
            }
        };

        let modified = self.mark_extensions_recursive(&mut value, 0);
        if !modified {
            return None;
        }

        match sonic_rs::to_vec(&value) {
            Ok(modified_bytes) => Some(Bytes::from(modified_bytes)),
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    "Failed to serialize modified VSCode response; passing original through"
                );
                None
            }
        }
    }

    /// Recursively walks a JSON value and rewrites any objects that *look like* VS Code
    /// Marketplace extension entries. This is deliberately schema-tolerant.
    fn mark_extensions_recursive(&self, value: &mut Value, depth: usize) -> bool {
        if depth >= MAX_MARKETPLACE_JSON_TRAVERSAL_DEPTH {
            tracing::trace!(
                max_depth = MAX_MARKETPLACE_JSON_TRAVERSAL_DEPTH,
                "VSCode response JSON traversal depth limit reached; stopping traversal"
            );
            return false;
        }

        if let Some(arr) = value.as_array_mut() {
            let mut modified = false;

            for child in arr.iter_mut() {
                modified |= self.mark_extensions_recursive(child, depth + 1);
            }

            return modified;
        }

        if let Some(obj) = value.as_object_mut() {
            let mut modified = false;

            for (_, child) in obj.iter_mut() {
                modified |= self.mark_extensions_recursive(child, depth + 1);
            }

            modified |= self.mark_extension_if_malware(value);
            return modified;
        }

        false
    }

    /// If `value` is a JSON object that looks like a VS Code Marketplace extension entry,
    /// rewrite it in-place when it matches the malware predicate.
    ///
    /// - The object must contain enough fields to build an extension id (`publisher.name`).
    /// - And it must also contain an "extension-ish" field (`displayName`).
    ///
    /// Returns `true` if the object was rewritten.
    fn mark_extension_if_malware(&self, value: &mut Value) -> bool {
        let (malware_display, extension_id) = {
            let Some(obj) = value.as_object() else {
                return false;
            };

            let display_name = match obj.get(&"displayName").and_then(|v| v.as_str()) {
                Some(name) => name,
                None => return false,
            };

            let extension_id = match Self::extract_extension_id(obj) {
                Some(id) => id,
                None => return false,
            };

            if !self.is_extension_id_malware(extension_id.as_str()) {
                return false;
            }

            (format!("⛔ MALWARE: {display_name}"), extension_id)
        };

        tracing::info!(
            package = %extension_id,
            "marked malware VSCode extension as blocked in API response"
        );

        if let Some(obj_mut) = value.as_object_mut() {
            Self::rewrite_extension_object(obj_mut, &malware_display);
        }
        true
    }

    /// Extracts the extension ID from a JSON object by looking up publisher and name fields.
    /// Returns None if required fields are missing or invalid.
    fn extract_extension_id(obj: &sonic_rs::Object) -> Option<SmolStr> {
        fn get_trimmed<'a>(obj: &'a sonic_rs::Object, key: &str) -> Option<&'a str> {
            obj.get(&key)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        }

        let publisher = obj
            .get(&"publisher")
            .and_then(|p| p.as_object())
            .and_then(|p| get_trimmed(p, "publisherName").or_else(|| get_trimmed(p, "name")))
            .or_else(|| get_trimmed(obj, "publisherName"))?;

        let name = get_trimmed(obj, "extensionName").or_else(|| get_trimmed(obj, "name"))?;

        Some(format_smolstr!("{publisher}.{name}"))
    }

    fn rewrite_extension_object(obj: &mut sonic_rs::Object, malware_display: &str) {
        obj.insert("displayName", Value::from(malware_display));

        const BLOCK_MSG: &str = "This extension has been marked as malware by Aikido safe-chain. Installation will be blocked.";

        obj.insert("shortDescription", Value::from(BLOCK_MSG));
    }
}

#[cfg(test)]
mod tests {
    include!("marketplace_json_tests.rs");
}
