pub fn is_chromium_browser_process_path(process_path: &str) -> bool {
    any_ends_with_ignore_ascii_case(
        process_path,
        &[
            "\\chrome.exe",
            "\\chromium.exe",
            "\\msedge.exe",
            "\\brave.exe",
            "\\opera.exe",
            "\\opera_gx.exe",
            "\\vivaldi.exe",
            "\\arc.exe",
            "\\yandex.exe",
            "\\thorium.exe",
        ],
    )
}

// utils below borrowed from rama-utils (soon those parts will be no-std compatible and we can
// clean up a lot of no std code in this repo)

fn any_ends_with_ignore_ascii_case<T, I>(s: T, sub_iter: I) -> bool
where
    T: AsRef<[u8]>,
    I: IntoIterator<Item: AsRef<[u8]>>,
{
    let search_space = s.as_ref();
    sub_iter
        .into_iter()
        .any(|suffix| ends_with_ignore_ascii_case(search_space, suffix))
}

fn ends_with_ignore_ascii_case<T1, T2>(s: T1, sub: T2) -> bool
where
    T1: AsRef<[u8]>,
    T2: AsRef<[u8]>,
{
    let s = s.as_ref();
    let sub = sub.as_ref();
    let n = sub.len();

    let start_index = s.len().checked_sub(n);
    start_index
        .and_then(|i| s.get(i..))
        .is_some_and(|tail| tail.eq_ignore_ascii_case(sub))
}

#[cfg(test)]
#[path = "browser_tests.rs"]
mod tests;
