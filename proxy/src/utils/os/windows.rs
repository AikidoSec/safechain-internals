pub fn raise_nofile(_target: u64) -> std::io::Result<()> {
    // on windows there's no such limit and it's more about
    // other resource usage which also has high limits by default
    Ok(())
}
