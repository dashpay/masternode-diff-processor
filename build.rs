extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut config: cbindgen::Config = Default::default();
    config.language = cbindgen::Language::C;
    match cbindgen::generate_with_config(&crate_dir, config) {
        Result::Ok(bindings) => bindings.write_to_file("target/mndiff.h"),
        Result::Err(err) => {
            eprintln!("Error generating: {}", err);
            false
        }
    };
}
