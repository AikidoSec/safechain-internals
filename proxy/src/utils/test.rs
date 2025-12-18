use std::time::{SystemTime, UNIX_EPOCH};

pub fn unique_empty_temp_dir(prefix: &str) -> std::io::Result<std::path::PathBuf> {
    let base = std::env::temp_dir();
    let pid = std::process::id();

    for attempt in 0..1000u32 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let dir = base.join(format!("{prefix}_{pid}_{nanos}_{attempt}"));
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "failed to create unique temp dir",
    ))
}
