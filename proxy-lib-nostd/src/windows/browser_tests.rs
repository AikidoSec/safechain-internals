use super::is_chromium_browser_process_path;

#[test]
fn detects_common_chromium_browsers_on_windows() {
    assert!(is_chromium_browser_process_path(
        "\\Device\\HarddiskVolume4\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    ));
    assert!(is_chromium_browser_process_path(
        "\\Device\\HarddiskVolume4\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    ));
    assert!(is_chromium_browser_process_path(
        "\\Device\\HarddiskVolume4\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
    ));
}

#[test]
fn ignores_non_chromium_binaries() {
    assert!(!is_chromium_browser_process_path(
        "\\Device\\HarddiskVolume4\\Windows\\System32\\curl.exe"
    ));
    assert!(!is_chromium_browser_process_path(
        "\\Device\\HarddiskVolume4\\Program Files\\Mozilla Firefox\\firefox.exe"
    ));
}
