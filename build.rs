extern crate gcc;

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
        .define("NDEBUG", None)
        .define("POSIX", None)
        //.define("WIN32", None)
        .flag("-std=c++14")
//        .flag("-fsanitize=undefined")
        .flag("-Wno-sign-compare")
        .flag("-fpermissive")
        .flag("-pthread")
        .compile("libutp_crust.a");
}
