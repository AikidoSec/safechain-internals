use rama::telemetry::tracing;

pub use libc::rlim_t;

pub fn raise_nofile(target: rlim_t) -> std::io::Result<()> {
    use std::{io, mem};

    unsafe {
        let mut lim: libc::rlimit = mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return Err(io::Error::last_os_error());
        }

        let hard = lim.rlim_max;
        let new_soft = target.min(hard);

        if lim.rlim_cur >= new_soft {
            tracing::info!(
                "ulimit: keep current limit ({}) as it is higher than new soft limit ({new_soft}): nothing to do",
                lim.rlim_cur,
            );
            return Ok(());
        }

        let previous_value = lim.rlim_cur;
        lim.rlim_cur = new_soft;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
            return Err(io::Error::last_os_error());
        }
        tracing::info!(
            "ulimit: applied new soft limit ({new_soft}); previous value = {previous_value}",
        );
    }

    Ok(())
}
