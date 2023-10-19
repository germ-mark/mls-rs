use std::{
    ffi::{c_char, c_void, CString},
    marker::PhantomData,
    mem,
    ptr::null_mut,
};

use aws_lc_sys::{
    sk_free, sk_new_null, sk_pop, sk_push, stack_st, ASN1_OBJECT_free, ASN1_STRING_free,
    ASN1_STRING_set, ASN1_STRING_type_new, GENERAL_NAME_free, GENERAL_NAME_new,
    GENERAL_NAME_set0_value, NID_basic_constraints, NID_commonName, NID_countryName,
    NID_distinguishedName, NID_domainComponent, NID_generationQualifier, NID_givenName,
    NID_initials, NID_key_usage, NID_localityName, NID_organizationName,
    NID_organizationalUnitName, NID_pkcs9_emailAddress, NID_pseudonym, NID_serialNumber,
    NID_stateOrProvinceName, NID_streetAddress, NID_subject_alt_name, NID_surname, NID_title,
    NID_userId, OBJ_txt2obj, X509V3_EXT_conf_nid, X509V3_EXT_i2d, X509_EXTENSION_free,
    X509_NAME_add_entry_by_NID, X509_NAME_free, X509_NAME_new, X509_name_st, ASN1_OBJECT,
    ASN1_STRING, GENERAL_NAME, GEN_DNS, GEN_EMAIL, GEN_RID, GEN_URI, MBSTRING_UTF8,
    V_ASN1_IA5STRING, V_ASN1_OCTET_STRING, X509_EXTENSION,
};
use aws_mls_identity_x509::{SubjectAltName, SubjectComponent};

use crate::{check_non_null, check_res, AwsLcCryptoError};

pub struct X509Name(pub(crate) *mut X509_name_st);

impl X509Name {
    pub fn new() -> Result<Self, AwsLcCryptoError> {
        unsafe { check_non_null(X509_NAME_new()).map(Self) }
    }

    pub fn add_entry(&mut self, component: &SubjectComponent) -> Result<(), AwsLcCryptoError> {
        let (nid, v) = match component {
            SubjectComponent::CommonName(cn) => (NID_commonName, cn),
            SubjectComponent::Surname(s) => (NID_surname, s),
            SubjectComponent::SerialNumber(s) => (NID_serialNumber, s),
            SubjectComponent::CountryName(c) => (NID_countryName, c),
            SubjectComponent::Locality(l) => (NID_localityName, l),
            SubjectComponent::State(s) => (NID_stateOrProvinceName, s),
            SubjectComponent::StreetAddress(a) => (NID_streetAddress, a),
            SubjectComponent::OrganizationName(on) => (NID_organizationName, on),
            SubjectComponent::OrganizationalUnit(ou) => (NID_organizationalUnitName, ou),
            SubjectComponent::Title(t) => (NID_title, t),
            SubjectComponent::GivenName(gn) => (NID_givenName, gn),
            SubjectComponent::EmailAddress(e) => (NID_pkcs9_emailAddress, e),
            SubjectComponent::UserId(u) => (NID_userId, u),
            SubjectComponent::DomainComponent(dc) => (NID_domainComponent, dc),
            SubjectComponent::Initials(i) => (NID_initials, i),
            SubjectComponent::GenerationQualifier(gq) => (NID_generationQualifier, gq),
            SubjectComponent::DistinguishedNameQualifier(dnq) => (NID_distinguishedName, dnq),
            SubjectComponent::Pseudonym(p) => (NID_pseudonym, p),
        };

        unsafe {
            check_res(X509_NAME_add_entry_by_NID(
                self.0,
                nid,
                MBSTRING_UTF8,
                v.as_ptr() as *mut _,
                v.len()
                    .try_into()
                    .map_err(|_| AwsLcCryptoError::CryptoError)?,
                -1,
                0,
            ))
        }
    }

    pub fn new_components(components: &[SubjectComponent]) -> Result<Self, AwsLcCryptoError> {
        components
            .iter()
            .try_fold(X509Name::new()?, |mut name, component| {
                name.add_entry(component)?;
                Ok(name)
            })
    }
}

impl Drop for X509Name {
    fn drop(&mut self) {
        unsafe { X509_NAME_free(self.0) }
    }
}

struct Asn1String(*mut ASN1_STRING);

impl Asn1String {
    pub fn new(string_type: i32) -> Result<Self, AwsLcCryptoError> {
        unsafe { check_non_null(ASN1_STRING_type_new(string_type)).map(Self) }
    }

    pub fn new_value(string_type: i32, value: &str) -> Result<Self, AwsLcCryptoError> {
        let mut new_val = Self::new(string_type)?;
        new_val.set_value(value)?;

        Ok(new_val)
    }

    pub fn set_value(&mut self, value: &str) -> Result<(), AwsLcCryptoError> {
        unsafe {
            check_res(ASN1_STRING_set(
                self.0,
                value.as_bytes().as_ptr() as *const c_void,
                value
                    .len()
                    .try_into()
                    .map_err(|_| AwsLcCryptoError::CryptoError)?,
            ))
        }
    }
}

impl From<Asn1String> for *mut c_void {
    fn from(val: Asn1String) -> Self {
        let inner = val.0 as *mut c_void;

        core::mem::forget(val);
        inner
    }
}

impl Drop for Asn1String {
    fn drop(&mut self) {
        unsafe { ASN1_STRING_free(self.0) }
    }
}

struct Asn1Object(*mut ASN1_OBJECT);

impl Asn1Object {
    pub fn from_string(string: &str) -> Result<Self, AwsLcCryptoError> {
        unsafe {
            let string = CString::new(string).map_err(|_| AwsLcCryptoError::CryptoError)?;

            check_non_null(OBJ_txt2obj(string.as_ptr() as *const c_char, 0)).map(Self)
        }
    }
}

impl From<Asn1Object> for *mut c_void {
    fn from(val: Asn1Object) -> Self {
        let inner = val.0 as *mut c_void;
        mem::forget(val);
        inner
    }
}

impl Drop for Asn1Object {
    fn drop(&mut self) {
        unsafe { ASN1_OBJECT_free(self.0) }
    }
}

pub(super) struct GeneralName(*mut GENERAL_NAME);

impl GeneralName {
    unsafe fn new() -> Result<Self, AwsLcCryptoError> {
        check_non_null(GENERAL_NAME_new()).map(Self)
    }

    fn new_value<T: Into<*mut c_void>>(name_type: i32, value: T) -> Result<Self, AwsLcCryptoError> {
        unsafe {
            let name = Self::new()?;

            GENERAL_NAME_set0_value(name.0, name_type, value.into());

            Ok(name)
        }
    }

    pub fn email(addr: &str) -> Result<Self, AwsLcCryptoError> {
        Self::new_value(GEN_EMAIL, Asn1String::new_value(V_ASN1_IA5STRING, addr)?)
    }

    pub fn uri(uri: &str) -> Result<Self, AwsLcCryptoError> {
        Self::new_value(GEN_URI, Asn1String::new_value(V_ASN1_IA5STRING, uri)?)
    }

    pub fn dns(dns: &str) -> Result<Self, AwsLcCryptoError> {
        Self::new_value(GEN_DNS, Asn1String::new_value(V_ASN1_IA5STRING, dns)?)
    }

    pub fn rid(rid: &str) -> Result<Self, AwsLcCryptoError> {
        Self::new_value(GEN_RID, Asn1Object::from_string(rid)?)
    }

    pub fn ip(ip: &str) -> Result<Self, AwsLcCryptoError> {
        Self::new_value(GEN_URI, Asn1String::new_value(V_ASN1_OCTET_STRING, ip)?)
    }
}

impl Drop for GeneralName {
    fn drop(&mut self) {
        unsafe { GENERAL_NAME_free(self.0) }
    }
}

impl From<*mut c_void> for GeneralName {
    fn from(value: *mut c_void) -> Self {
        Self(value as *mut GENERAL_NAME)
    }
}

impl From<GeneralName> for *mut c_void {
    fn from(val: GeneralName) -> Self {
        let inner = val.0 as *mut c_void;
        mem::forget(val);
        inner
    }
}

pub struct Stack<T>
where
    T: Into<*mut c_void> + From<*mut c_void>,
{
    pub(crate) inner: *mut stack_st,
    phantom: PhantomData<T>,
}

impl<T> Stack<T>
where
    T: Into<*mut c_void> + From<*mut c_void>,
{
    pub fn new() -> Result<Self, AwsLcCryptoError> {
        unsafe {
            check_non_null(sk_new_null()).map(|v| Self {
                inner: v,
                phantom: Default::default(),
            })
        }
    }

    pub fn push(&mut self, val: T) {
        unsafe {
            sk_push(self.inner, val.into());
        }
    }
}

impl<T> Drop for Stack<T>
where
    T: Into<*mut c_void> + From<*mut c_void>,
{
    fn drop(&mut self) {
        unsafe {
            loop {
                let val = sk_pop(self.inner);

                if val.is_null() {
                    break;
                }

                let _ = T::from(val);
            }

            sk_free(self.inner)
        }
    }
}

pub enum KeyUsage {
    DigitalSignature,
    NonRepudiation,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}

impl KeyUsage {
    pub fn as_str(&self) -> &str {
        match self {
            KeyUsage::DigitalSignature => "digitalSignature",
            KeyUsage::NonRepudiation => "nonRepudiation",
            KeyUsage::KeyEncipherment => "keyEncipherment",
            KeyUsage::DataEncipherment => "dataEncipherment",
            KeyUsage::KeyAgreement => "keyAgreement",
            KeyUsage::KeyCertSign => "keyCertSign",
            KeyUsage::CrlSign => "cRLSign",
            KeyUsage::EncipherOnly => "encipherOnly",
            KeyUsage::DecipherOnly => "decipherOnly",
        }
    }
}

pub struct X509Extension(*mut X509_EXTENSION);

impl X509Extension {
    pub fn subject_alt_name(alt_names: &[SubjectAltName]) -> Result<Self, AwsLcCryptoError> {
        let stack = alt_names
            .iter()
            .try_fold(Stack::new()?, |mut names, name| {
                let general_name = match name {
                    SubjectAltName::Email(email) => GeneralName::email(email),
                    SubjectAltName::Uri(uri) => GeneralName::uri(uri),
                    SubjectAltName::Dns(dns) => GeneralName::dns(dns),
                    SubjectAltName::Rid(rid) => GeneralName::rid(rid),
                    SubjectAltName::Ip(ip) => GeneralName::ip(ip),
                }?;

                names.push(general_name);

                Ok::<_, AwsLcCryptoError>(names)
            })?;

        unsafe {
            check_non_null(X509V3_EXT_i2d(NID_subject_alt_name, 0, stack.inner.cast())).map(Self)
        }
    }

    pub fn basic_constraints(
        critical: bool,
        ca: bool,
        path_len: Option<u32>,
    ) -> Result<Self, AwsLcCryptoError> {
        let mut basic_constraints = String::new();

        if critical {
            basic_constraints.push_str("critical,");
        }

        if ca {
            basic_constraints.push_str("CA:TRUE");
        } else {
            basic_constraints.push_str("CA:FALSE");
        }

        if let Some(path_len) = path_len {
            basic_constraints.push_str(format!(",pathlen{}", path_len).as_str());
        }

        string_to_ext(basic_constraints, NID_basic_constraints)
    }

    pub fn key_usage(critical: bool, usages: &[KeyUsage]) -> Result<Self, AwsLcCryptoError> {
        let mut key_usage = String::new();

        if critical {
            key_usage.push_str("critical");
        }

        usages.iter().for_each(|usage| {
            key_usage.push(',');
            key_usage.push_str(usage.as_str());
        });

        string_to_ext(key_usage, NID_key_usage)
    }
}

impl From<X509Extension> for *mut c_void {
    fn from(value: X509Extension) -> Self {
        let inner = value.0;
        core::mem::forget(value);
        inner.cast()
    }
}

impl From<*mut c_void> for X509Extension {
    fn from(value: *mut c_void) -> Self {
        X509Extension(value.cast())
    }
}

impl Drop for X509Extension {
    fn drop(&mut self) {
        unsafe { X509_EXTENSION_free(self.0) }
    }
}

fn string_to_ext(string: String, nid: i32) -> Result<X509Extension, AwsLcCryptoError> {
    let c_string = CString::new(string).map_err(|_| AwsLcCryptoError::CryptoError)?;

    unsafe {
        check_non_null(X509V3_EXT_conf_nid(
            null_mut(),
            null_mut(),
            nid,
            c_string.as_ptr(),
        ))
        .map(X509Extension)
    }
}