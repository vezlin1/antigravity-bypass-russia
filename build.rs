fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/icon.ico");

    #[cfg(windows)]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
            let mut res = winres::WindowsResource::new();
            if std::path::Path::new("assets/icon.ico").exists() {
                res.set_icon("assets/icon.ico");
            }
            res.set(
                "FileDescription",
                "Antigravity Bypass Russia & Rollback Tool",
            );
            res.set("ProductName", "ANTIGRAVITY-BYPASS-RUSSIA");
            res.set("OriginalFilename", "antigravity-bypass-windows.exe");
            res.set(
                "LegalCopyright",
                "Copyright (c) 2026 Antigravity Contributors",
            );
            let ver = std::env::var("CARGO_PKG_VERSION").expect("Cargo package version");
            res.set("FileVersion", &ver);
            res.set("ProductVersion", &ver);

            res.set_manifest(
                r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
            <requestedExecutionLevel level="asInvoker" uiAccess="false" />
        </requestedPrivileges>
    </security>
</trustInfo>
</assembly>
"#,
            );
            res.compile()
                .expect("Windows resources/manifest compilation failed");
        }
    }
}
