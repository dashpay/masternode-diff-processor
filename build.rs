extern crate cbindgen;

use std::env;
// use std::path::PathBuf;

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

    // let lib = vcpkg::Config::new()
    //     .emit_includes(true)
    //     .find_package("presentmon")
    //     .expect("vcpkg failed");
    //
    // let mut include_dirs: Vec<String> = Vec::new();
    // for path in lib.include_paths {
    //     for subdir in WalkDir::new(path)
    //         .into_iter()
    //         .filter_entry(|e| e.file_type().is_dir())
    //     {
    //         let dir = subdir.unwrap().path().to_string_lossy().to_string();
    //         include_dirs.push(format!("--include-directory={}", dir));
    //     }
    // }

    /*

    // clang version must have been 3.9+
    bindgen::Builder::default()
        .header("blswrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // .clang_arg("-v")
        // .clang_args(include_dirs)
        .clang_args(&["-x","c++","-std=c++14"])
        .clang_arg("-I../bls-signatures/contrib/relic/include")
        .clang_arg("-I../bls-signatures/build/contrib/relic/include")
        .clang_arg("-I../bls-signatures/src/")
        // .clang_arg("-L../bls-signatures/build/")
        // .clang_arg("-../bls-signatures/build/libchiabls.a")
        .generate()
        .expect("unable to generate bindings")
        .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs"))
        .expect("couldn't write bindings");

    */
}
