use std::fs;
use std::path::Path;

fn main() {
    download_geosite();
    let mut config = prost_build::Config::new();
    config.bytes(["."]);
    //config.type_attribute(".", "#[derive(PartialOrd)]");
    config
        .out_dir("src/")
        .compile_protos(&["src/proto/geosite.proto"], &["src/"])
        .unwrap();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/proto/geosite.proto");
    println!("cargo:rerun-if-changed=deps/*");
}

fn download_geosite() {
    let url = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat";
    let path = Path::new(".").join("deps");
    fs::create_dir_all(path.clone()).unwrap();
    let path = path.join("geosite.dat");
    if path.exists() {
        return;
    }
    let mut resp = reqwest::blocking::get(url).unwrap();
    let mut file = fs::File::create(path).unwrap();
    resp.copy_to(&mut file).unwrap();
}
