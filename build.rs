extern crate gcc;

#[cfg(not(target_os="windows"))]
fn main() {
    gcc::Config::new()
        .cpp(true)
        .file("libutp_crust/utp_internal.cpp")
        .file("libutp_crust/utp_utils.cpp")
        .file("libutp_crust/utp_hash.cpp")
        .file("libutp_crust/utp_callbacks.cpp")
        .file("libutp_crust/utp_api.cpp")
        .file("libutp_crust/utp_packedsockaddr.cpp")
        .file("libutp_crust/utp_crust.cpp")
        .define("UTP_DEBUG_LOGGING", None)
        .flag("-std=c++14")
//        .flag("-fsanitize=undefined")
        .flag("-Wno-sign-compare")
        .flag("-fpermissive")
        .flag("-pthread")
        .define("POSIX", None)
        .compile("libutp_crust.a");        
}

#[cfg(target_os="windows")]
fn main() {
    gcc::Config::new()
        .cpp(true)
        .file("libutp_crust/utp_internal.cpp")
        .file("libutp_crust/utp_utils.cpp")
        .file("libutp_crust/utp_hash.cpp")
        .file("libutp_crust/utp_callbacks.cpp")
        .file("libutp_crust/utp_api.cpp")
        .file("libutp_crust/utp_packedsockaddr.cpp")
        .file("libutp_crust/utp_crust.cpp")
        .define("UTP_DEBUG_LOGGING", None)
        .flag("-std=c++14")
//        .flag("-fsanitize=undefined")
        .flag("-Wno-sign-compare")
        .flag("-fpermissive")
        .flag("-pthread")
        .define("WIN32", None)
        .compile("libutp_crust.a");        
}
