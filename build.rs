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
            res.set("FileDescription", "Antigravity Bypass Russia & Rollback Tool");
            res.set("ProductName", "ANTIGRAVITY-BYPASS-RUSSIA");
            res.set("OriginalFilename", "antigravity-bypass-russia.exe");
            res.set("LegalCopyright", "Copyright (c) 2026 Antigravity Contributors");
            res.set("FileVersion", "1.0.0");
            res.set("ProductVersion", "1.0.0");
            
            res.set_manifest(r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
            <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
        </requestedPrivileges>
    </security>
</trustInfo>
</assembly>
"#);
            let _ = res.compile();
        }
    }
}
