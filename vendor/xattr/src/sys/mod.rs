macro_rules! platforms {
    ($($($platform:expr);* => $module:ident),*) => {
        $(
            #[cfg(any($(target_os = $platform),*))]
            mod $module;

            #[cfg(any($(target_os = $platform),*))]
            pub use self::$module::*;

            #[cfg(any($(target_os = $platform),*))]
            // Linux names a missing extended attribute ENODATA. New libc releases
            // no longer provide the historical ENOATTR alias.
            #[cfg(any(target_os = "linux", target_os = "android"))]
            pub(crate) const ENOATTR: ::libc::c_int = ::libc::ENODATA;
            #[cfg(any($(target_os = $platform),*))]
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            pub(crate) const ENOATTR: ::libc::c_int = ::libc::ENOATTR;
        )*

        #[cfg(all(feature = "unsupported", not(any($($(target_os = $platform),*),*))))]
        mod unsupported;

        #[cfg(all(feature = "unsupported", not(any($($(target_os = $platform),*),*))))]
        pub use self::unsupported::*;
        #[cfg(all(feature = "unsupported", not(any($($(target_os = $platform),*),*))))]
        pub(crate) const ENOATTR: ::libc::c_int = 0;


        /// A constant indicating whether or not the target platform is supported.
        ///
        /// To make programmer's lives easier, this library builds on all platforms.
        /// However, all function calls on unsupported platforms will return
        /// `io::Error`s.
        ///
        /// Note: If you would like compilation to simply fail on unsupported platforms,
        /// turn of the `unsupported` feature.
        pub const SUPPORTED_PLATFORM: bool = cfg!(any($($(target_os = $platform),*),*));
    }
}

platforms! {
    "android"; "linux"; "macos" => linux_macos,
    "freebsd"; "netbsd" => bsd
}
