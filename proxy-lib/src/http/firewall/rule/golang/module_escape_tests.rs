use super::go_module_unescape;

#[test]
fn empty_string() {
    assert_eq!(go_module_unescape(""), "");
}

#[test]
fn no_uppercase() {
    // Common case — all-lowercase paths are not modified at all
    assert_eq!(go_module_unescape("gorilla"), "gorilla");
}

#[test]
fn all_lowercase_proxy_path() {
    assert_eq!(
        go_module_unescape("github.com/gorilla/mux"),
        "github.com/gorilla/mux"
    );
}

#[test]
fn single_leading_uppercase() {
    // "Azure" → escaped as "!azure"
    assert_eq!(go_module_unescape("!azure"), "Azure");
}

#[test]
fn multiple_uppercases() {
    // "AikidoSec" → escaped as "!aikido!sec"
    assert_eq!(go_module_unescape("!aikido!sec"), "AikidoSec");
}

#[test]
fn uppercase_in_org_only() {
    // "GoogleCloudPlatform/cloudsql-proxy" → "!google!cloud!platform/cloudsql-proxy"
    assert_eq!(
        go_module_unescape("!google!cloud!platform/cloudsql-proxy"),
        "GoogleCloudPlatform/cloudsql-proxy"
    );
}

#[test]
fn uppercase_in_repo_only() {
    assert_eq!(go_module_unescape("org/!my!repo"), "org/MyRepo");
}

#[test]
fn mixed_segments_only_first_encoded() {
    // "Azure/azure-sdk-for-go" — org is capitalized, repo is not
    assert_eq!(
        go_module_unescape("!azure/azure-sdk-for-go"),
        "Azure/azure-sdk-for-go"
    );
}

#[test]
fn consecutive_uppercases() {
    // "ABC" → "!a!b!c"
    assert_eq!(go_module_unescape("!a!b!c"), "ABC");
}

#[test]
fn sirupsen_logrus() {
    // Real-world: "Sirupsen/logrus" is a well-known module with an uppercase org
    assert_eq!(go_module_unescape("!sirupsen/logrus"), "Sirupsen/logrus");
}

#[test]
fn full_proxy_path_with_escaping() {
    // Full path as it appears after percent-decoding the proxy URL
    assert_eq!(
        go_module_unescape("github.com/!sirupsen/logrus"),
        "github.com/Sirupsen/logrus"
    );
}

// --- Invalid / defensive cases ---

#[test]
fn invalid_escape_bang_at_end() {
    // Trailing `!` with nothing after it — passed through unchanged
    assert_eq!(go_module_unescape("foo!"), "foo!");
}

#[test]
fn invalid_escape_bang_followed_by_uppercase() {
    // `!!bar` — first `!` is not a valid escape (followed by `!`, not a-z) so it passes
    // through; the second `!b` is a valid escape and becomes `B`.
    // Go never produces `!!` in real paths, but each `!` is processed independently.
    assert_eq!(go_module_unescape("foo!!bar"), "foo!Bar");
}

#[test]
fn invalid_escape_bang_followed_by_digit() {
    // `!1` — not a valid Go escape sequence, passed through
    assert_eq!(go_module_unescape("foo!1bar"), "foo!1bar");
}

#[test]
fn invalid_escape_bang_followed_by_space() {
    assert_eq!(go_module_unescape("foo! bar"), "foo! bar");
}
