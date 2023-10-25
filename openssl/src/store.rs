use crate::error::ErrorStack;
use crate::lib_ctx::LibCtxRef;
use crate::pkey::{PKey, Private};
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;
use openssl_macros::corresponds;
use std::ffi::CString;
use std::ptr;

/// The type of an Store Info.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct StoreInfoType(c_int);

// # define OSSL_STORE_INFO_NAME           1   /* char * */
// # define OSSL_STORE_INFO_PARAMS         2   /* EVP_PKEY * */
// # define OSSL_STORE_INFO_PUBKEY         3   /* EVP_PKEY * */
// # define OSSL_STORE_INFO_PKEY           4   /* EVP_PKEY * */
// # define OSSL_STORE_INFO_CERT           5   /* X509 * */
// # define OSSL_STORE_INFO_CRL            6   /* X509_CRL * */
#[allow(missing_docs)] // no need to document the constants
impl StoreInfoType {
    pub const NAME: StoreInfoType = StoreInfoType(ffi::OSSL_STORE_INFO_NAME);

    pub const PARAMS: StoreInfoType = StoreInfoType(ffi::OSSL_STORE_INFO_PARAMS);

    pub const PUBKEY: StoreInfoType = StoreInfoType(ffi::OSSL_STORE_INFO_PUBKEY);

    pub const PKEY: StoreInfoType = StoreInfoType(ffi::OSSL_STORE_INFO_PKEY);

    pub const CERT: StoreInfoType = StoreInfoType(ffi::OSSL_STORE_INFO_CERT);

    pub const CRL: StoreInfoType = StoreInfoType(ffi::OSSL_STORE_INFO_CRL);

    /// Constructs an `StoreInfoType` from a raw OpenSSL value.
    pub fn from_raw(value: c_int) -> Self {
        StoreInfoType(value)
    }

    /// Returns the raw OpenSSL value represented by this type.
    pub fn as_raw(&self) -> c_int {
        self.0
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_STORE_CTX;
    fn drop = ossl_store_free;

    pub struct Store;
    /// A reference to a [`Provider`].
    pub struct StoreRef;
}

#[inline]
unsafe fn ossl_store_free(s: *mut ffi::OSSL_STORE_CTX) {
    ffi::OSSL_STORE_close(s);
}

impl Store {
    /// Loads a new provider into the specified library context, disabling the fallback providers.
    ///
    /// If `ctx` is `None`, the provider will be loaded in to the default library context.
    #[corresponds(OSSL_STORE_open_ex)]
    pub fn open_ex(
        uri: &str,
        ctx: Option<&LibCtxRef>,
        propq: Option<&str>,
    ) -> Result<Self, ErrorStack> {
        let uri = CString::new(uri).unwrap();
        let propq = propq.map(|p| CString::new(p).unwrap());
        unsafe {
            let p = cvt_p(ffi::OSSL_STORE_open_ex(
                uri.as_ptr(),
                ctx.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr),
                propq.map_or(ptr::null_mut(), |p| p.as_ptr()),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                None,
                ptr::null_mut(),
            ))?;

            Ok(Store::from_ptr(p))
        }
    }

    /// Loads a new provider into the specified library context, disabling the fallback providers if `retain_fallbacks`
    /// is `false` and the load succeeds.
    ///
    /// If `ctx` is `None`, the provider will be loaded into the default library context.
    #[corresponds(OSSL_STORE_load)]
    pub fn try_load(ctx: Option<&Store>) -> Result<StoreInfo, ErrorStack> {
        unsafe {
            let p = cvt_p(ffi::OSSL_STORE_load(
                ctx.map_or(ptr::null_mut(), |c| c.as_ptr()),
            ))?;

            Ok(StoreInfo::from_ptr(p))
        }
    }

    /// Specifies the default search path that is to be used for looking for providers in the specified library context.
    /// If left unspecified, an environment variable and a fall back default value will be used instead
    ///
    /// If `ctx` is `None`, the provider will be loaded into the default library context.
    #[corresponds(OSSL_STORE_INFO_get_type)]
    pub fn get_type(info: &StoreInfo) -> Result<StoreInfoType, ErrorStack> {
        unsafe {
            let store_type = cvt(ffi::OSSL_STORE_INFO_get_type(info.as_ptr()))?;

            Ok(StoreInfoType::from_raw(store_type))
        }
    }

    /// Get the Private Key of the given Store
    ///
    /// Make sure that the Store Info type is `StoreInfoType::PKey` when using this function
    #[corresponds(OSSL_STORE_INFO_get1_PKEY)]
    pub fn get_pkey(info: &StoreInfo) -> Result<PKey<Private>, ErrorStack> {
        unsafe {
            let evp_pkey = cvt_p(ffi::OSSL_STORE_INFO_get1_PKEY(info.as_ptr()))?;

            Ok(PKey::from_ptr(evp_pkey))
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_STORE_INFO;
    fn drop = ffi::OSSL_STORE_INFO_free;

    pub struct StoreInfo;
    /// A reference to a [`StoreInfo`].
    pub struct StoreInfoRef;
}
