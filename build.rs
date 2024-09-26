use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const FILESNOOP_SOURCE: &str = "src/bpf/filesnoop.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"))
        .join("filesnoop.skel.rs");

    SkeletonBuilder::new()
        .source(FILESNOOP_SOURCE)
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={FILESNOOP_SOURCE}");
}
