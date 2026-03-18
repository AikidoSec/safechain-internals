use core::ffi::c_void;
use core_foundation::{base::TCFType, string::CFString};

use rama::{
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    telemetry::tracing,
    tls::boring::core::{
        ec::EcKey,
        pkey::{Id, PKey, Private},
        rsa::Rsa,
        x509::X509,
    },
};
use safechain_proxy_lib::tls::RootCaKeyPair;
use security_framework::{
    item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult},
    key::SecKey,
};

use crate::utils::env::{L4_PROXY_HOST_BUNDLE_ID, MANAGED_VPN_SHARED_ACCESS_GROUP};

pub(crate) fn load_root_ca_key_pair(
    use_vpn_shared_identity: bool,
) -> Result<Option<RootCaKeyPair>, BoxError> {
    if !use_vpn_shared_identity {
        return Ok(None);
    }

    tracing::info!(
        access_group = MANAGED_VPN_SHARED_ACCESS_GROUP,
        identity_label = L4_PROXY_HOST_BUNDLE_ID,
        "loading managed VPN shared CA identity"
    );

    let mut search = ItemSearchOptions::new();
    search
        .class(ItemClass::identity())
        .load_refs(true)
        .limit(Limit::Max(1))
        .label(L4_PROXY_HOST_BUNDLE_ID)
        .access_group(MANAGED_VPN_SHARED_ACCESS_GROUP)
        .ignore_legacy_keychains();

    let result = search
        .search()
        .context("search for managed VPN shared identity")?
        .into_iter()
        .next()
        .ok_or_else(|| {
            BoxError::from("managed VPN shared identity not found")
                .context_str_field("access_group", MANAGED_VPN_SHARED_ACCESS_GROUP)
                .context_str_field("identity_label", L4_PROXY_HOST_BUNDLE_ID)
        })?;

    let identity = match result {
        SearchResult::Ref(Reference::Identity(identity)) => identity,
        other => {
            return Err(
                BoxError::from("unexpected search result while loading managed identity")
                    .context_debug_field("search_result", format!("{other:?}")),
            );
        }
    };

    let certificate = identity
        .certificate()
        .context("copy certificate from managed identity")?;
    let key = identity
        .private_key()
        .context("copy private key from managed identity")?;

    let certificate = X509::from_der(&certificate.to_der())
        .context("parse managed identity certificate as X509")?;
    let private_key = export_private_key(&key).context("export managed identity private key")?;

    RootCaKeyPair::try_from_boring(certificate, private_key)
        .context("convert managed identity into RootCaKeyPair")
        .map(Some)
}

fn export_private_key(key: &SecKey) -> Result<PKey<Private>, BoxError> {
    let der = key
        .external_representation()
        .map(|data| data.to_vec())
        .ok_or_else(|| BoxError::from("managed identity private key is not exportable"))?;

    if let Ok(parsed_key) = PKey::private_key_from_der(&der) {
        return Ok(parsed_key);
    }

    let key_type = key_type(key).context("read managed identity private key type")?;

    match key_type {
        Id::RSA => {
            let rsa = Rsa::private_key_from_der(&der)
                .context("parse managed identity RSA private key from DER")?;
            PKey::from_rsa(rsa).context("wrap managed identity RSA key")
        }
        Id::EC => {
            let ec = EcKey::private_key_from_der(&der)
                .context("parse managed identity EC private key from DER")?;
            PKey::from_ec_key(ec).context("wrap managed identity EC key")
        }
        other => Err(
            BoxError::from("unsupported managed identity private key type")
                .context_debug_field("key_type", format!("{other:?}")),
        ),
    }
}

fn key_type(key: &SecKey) -> Result<Id, BoxError> {
    let attrs = key.attributes();
    let key_type_ptr = attrs
        .find(unsafe { security_framework_sys::item::kSecAttrKeyType }.cast::<c_void>())
        .map(|ptr| *ptr)
        .ok_or_else(|| BoxError::from("managed identity private key type attribute missing"))?;
    let key_type = unsafe { CFString::wrap_under_get_rule(key_type_ptr.cast()) };
    let rsa =
        unsafe { CFString::wrap_under_get_rule(security_framework_sys::item::kSecAttrKeyTypeRSA) };
    let ec_prime_random = unsafe {
        CFString::wrap_under_get_rule(security_framework_sys::item::kSecAttrKeyTypeECSECPrimeRandom)
    };

    if key_type == rsa {
        return Ok(Id::RSA);
    }
    if key_type == ec_prime_random {
        return Ok(Id::EC);
    }

    Err(BoxError::from("unsupported managed identity key type")
        .context_debug_field("key_type", key_type.to_string()))
}
