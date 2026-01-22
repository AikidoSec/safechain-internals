fn main() {
    #[cfg(target_os = "windows")]
    {
        static_vcruntime::metabuild();

        let mut res = winresource::WindowsResource::new();
        res.set_icon("../packaging/shared/icons/SafeChain.ico");
        res.set("ProductName", "SafeChain Ultimate");
        res.set("FileDescription", "SafeChain Proxy");
        res.set("CompanyName", "Aikido Security BV");
        res.set("LegalCopyright", "Copyright © Aikido Security BV");
        res.set("OriginalFilename", "SafeChainProxy.exe");
        res.compile().expect("Failed to compile Windows resources");
    }
}
