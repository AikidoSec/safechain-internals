fn main() {
    #[cfg(target_os = "windows")]
    {
        static_vcruntime::metabuild();

        let mut res = winresource::WindowsResource::new();
        res.set_icon("../packaging/shared/SafeChain.ico");
        res.set("ProductName", "SafeChain Proxy");
        res.set("FileDescription", "Aikido Security SafeChain Proxy");
        res.set("CompanyName", "Aikido Security BV");
        res.set("LegalCopyright", "Copyright © 2025 Aikido Security BV");
        res.compile().expect("Failed to compile Windows resources");
    }
}
