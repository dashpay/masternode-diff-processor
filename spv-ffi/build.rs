extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut config: cbindgen::Config =
        cbindgen::Config::from_file("./cbindgen.toml").expect("Error config");
    let mut parse_config: cbindgen::ParseConfig = cbindgen::ParseConfig::default();
    parse_config.parse_deps = true;
    parse_config.include = Some(vec!["dash-spv-models".to_string()]);
    parse_config.extra_bindings = vec!["dash-spv-models".to_string()];
    config.language = cbindgen::Language::C;
    config.parse = parse_config;
    cbindgen::generate_with_config(&crate_dir, config)
        .unwrap()
        .write_to_file("target/dash_spv_ffi.h");
}
