use super::super::*;
use libc::*;

// OSSL_STORE_CTX *
// OSSL_STORE_open_ex(const char *uri, OSSL_LIB_CTX *libctx, const char *propq,
//                    const UI_METHOD *ui_method, void *ui_data,
//                    const OSSL_PARAM params[],
//                    OSSL_STORE_post_process_info_fn post_process,
//                    void *post_process_data);

pub const OSSL_STORE_INFO_NAME: c_int = 1;
pub const OSSL_STORE_INFO_PARAMS: c_int = 2;
pub const OSSL_STORE_INFO_PUBKEY: c_int = 3;
pub const OSSL_STORE_INFO_PKEY: c_int = 4;
pub const OSSL_STORE_INFO_CERT: c_int = 5;
pub const OSSL_STORE_INFO_CRL: c_int = 6;

extern "C" {
    #[cfg(ossl300)]
    pub fn OSSL_STORE_open_ex(
        uri: *const c_char,
        ctx: *mut OSSL_LIB_CTX,
        propq: *const c_char,
        ui_method: *const UI_METHOD,
        ui_data: *mut c_void,
        params: *mut OSSL_PARAM,
        post_process: Option<
            unsafe extern "C" fn(*mut OSSL_STORE_INFO, *mut c_void) -> OSSL_STORE_INFO,
        >,
        post_process_data: *mut c_void,
    ) -> *mut OSSL_STORE_CTX;
    #[cfg(ossl300)]
    pub fn OSSL_STORE_load(ctx: *mut OSSL_STORE_CTX) -> *mut OSSL_STORE_INFO;
    #[cfg(ossl300)]
    pub fn OSSL_STORE_close(ctx: *mut OSSL_STORE_CTX) -> c_int;
    #[cfg(ossl300)]
    pub fn OSSL_STORE_INFO_get_type(info: *const OSSL_STORE_INFO) -> c_int;
    #[cfg(ossl300)]
    pub fn OSSL_STORE_INFO_get1_PKEY(info: *const OSSL_STORE_INFO) -> *mut EVP_PKEY;
    #[cfg(ossl300)]
    pub fn OSSL_STORE_INFO_get1_CERT(info: *const OSSL_STORE_INFO) -> *mut X509;
    #[cfg(ossl300)]
    pub fn OSSL_STORE_INFO_free(info: *mut OSSL_STORE_INFO);
}
