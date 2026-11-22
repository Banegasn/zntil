fn main() {
    let root = "vendor/libinjection";
    println!("cargo:rerun-if-changed={root}");
    cc::Build::new()
        .include(root)
        .file(format!("{root}/libinjection_sqli.c"))
        .file(format!("{root}/libinjection_xss.c"))
        .file(format!("{root}/libinjection_html5.c"))
        .warnings(false)
        .compile("injection");
}
