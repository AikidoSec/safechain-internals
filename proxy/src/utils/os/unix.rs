use rama::telemetry::tracing;

pub fn raise_nofile(target: u64) -> std::io::Result<()> {
    use std::{io, mem};

    unsafe {
        let mut lim: libc::rlimit = mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return Err(io::Error::last_os_error());
        }

        let hard = lim.rlim_max as u64;
        let new_soft = target.min(hard);

        if lim.rlim_cur as u64 >= new_soft {
            tracing::info!(
                "ulimit: keep current limit ({}) as it is higher than new soft limit ({new_soft}): nothing to do",
                lim.rlim_cur,
            );
            return Ok(());
        }

        let previous_value = lim.rlim_cur;
        lim.rlim_cur = new_soft as libc::rlim_t;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
            return Err(io::Error::last_os_error());
        }
        tracing::info!(
            "ulimit: applied new soft limit ({new_soft}); previous value = {previous_value}",
        );
    }

    Ok(())
}
