fn main() {
    #[cfg(target_os = "macos")]
    {
        cc::Build::new()
            .file("src/auth.m")
            .flag("-fmodules")
            .compile("cloak_auth");

        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }

    tauri_build::build();
}
