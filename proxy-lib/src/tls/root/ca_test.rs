use rama::{
    error::{BoxError, ErrorContext as _},
    tls::boring::core::{pkey::PKey, x509::X509},
};

use crate::{
    storage::{SyncCompactDataStorage, SyncSecrets},
    tls::RootCaKeyPair,
};

pub(in crate::tls) fn new_root_tls_crt_key_pair(
    _secrets: &SyncSecrets,
    _data_storage: &SyncCompactDataStorage,
) -> Result<RootCaKeyPair, BoxError> {
    let crt = X509::from_pem(E2E_STATIC_ROOT_CA_CERT_PEM.as_bytes())
        .context("parse static e2e CA certificate PEM")?;
    let key = PKey::private_key_from_pem(E2E_STATIC_ROOT_CA_KEY_PEM.as_bytes())
        .context("parse static e2e CA private key PEM")?;
    Ok(RootCaKeyPair::new(crt, key))
}
const E2E_STATIC_ROOT_CA_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIC8jCCAdoCCQDJI03q1nMwEzANBgkqhkiG9w0BAQsFADA7MRowGAYDVQQKDBFT
YWZlY2hhaW4gVGVzdCBDQTEdMBsGA1UEAwwUc2FmZWNoYWluLXRlc3QubG9jYWww
HhcNMjYwMzIzMTA1NzI5WhcNMzYwMzIwMTA1NzI5WjA7MRowGAYDVQQKDBFTYWZl
Y2hhaW4gVGVzdCBDQTEdMBsGA1UEAwwUc2FmZWNoYWluLXRlc3QubG9jYWwwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOE65Ej/8Tl60UulU+/C5UUDje
u2OSCcBz+76GlwqaPHwXEo/bfeWLfpdrt0favbLEJ3TTfpSeZsj/c/+7sud1A6Pq
JvtmpCouxHDU2UEj7AEURo26Kr7XJhZNTcAF32XjTAPjhJFTBp2bs/JUaMJd04qO
N3jTgWR65YPgf704lScHjqNfwWd0pj0glhGnjkNoJhT4LWuaoPiv3djj4VpUdq37
r8KP2LBUBYZdKPw2ZrXkg4MIBt/dfhSKpsGBbgLhiN3VuybiegPOUMS8HIGJ+KKm
su8+ZUNpH7O69V5OOJNPHeGCFZPVNLDtqQyLvpEJ5PAqp3Rz62pswDNxNr6ZAgMB
AAEwDQYJKoZIhvcNAQELBQADggEBAKupsMlEuwHB5kBRovCki7YWeCcqGNm7ruqF
JKeTNN2WxpZC3NgJ00Cb236SffiNzb0Qid+rVnyXzamYJ2oNZxBn4VRbHskbIJ98
vTuFUBHP03Hky6UgEqLvGPrRkzGGB+0w2QZzSdK0XfACEW8yt6dc+nES5Ixpjq8A
bxGQ+kTDBkoIhlXs6mE2yKjq3wg0zm4YUQZgvyQmxJhCOY0rKcsHnv1eZHLNJsA6
5bl4Zbm6e/s2qQIattmlp41g2v/x/Bl5Hd8nlad8ie0aJTsHI6OOv8w6hwHpY6Es
IwsD7yzulfL4HQYoGOr3qnR+a8CooUZiu5SlQ8fKeZrJmJqNedY=
-----END CERTIFICATE-----
"#;

const E2E_STATIC_ROOT_CA_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDOE65Ej/8Tl60U
ulU+/C5UUDjeu2OSCcBz+76GlwqaPHwXEo/bfeWLfpdrt0favbLEJ3TTfpSeZsj/
c/+7sud1A6PqJvtmpCouxHDU2UEj7AEURo26Kr7XJhZNTcAF32XjTAPjhJFTBp2b
s/JUaMJd04qON3jTgWR65YPgf704lScHjqNfwWd0pj0glhGnjkNoJhT4LWuaoPiv
3djj4VpUdq37r8KP2LBUBYZdKPw2ZrXkg4MIBt/dfhSKpsGBbgLhiN3VuybiegPO
UMS8HIGJ+KKmsu8+ZUNpH7O69V5OOJNPHeGCFZPVNLDtqQyLvpEJ5PAqp3Rz62ps
wDNxNr6ZAgMBAAECggEAUxkWjakvJ3xjG9ejZlmUaQVMWWxg01PBWkOqaWVgrh8z
vq4KemzC8kQi1Rm8DNWvz29Fqb8COPmjlXb2KX8T3FiScWo0uAf8xo0KHppYrR6O
tNlabzara+B838E5bGTQFh7h9o3PeBZT2aRvVGBF+EXEOmLeAxPLK89/JTj9WWH6
RSz5jAV/IAWinzAyc0lBE8sOUCALxcBvZdLPa5O5LGqxU4OT+bTSW9e3WV5hTUNQ
njZvhRTWbVz4trzW2gzfWJcBJaUW35nwksbRo0P/bctqsUz9831RbKtRfZG3l+bp
RlDXSe4M5Qz866dFVyhWIb2yLkjV8+CjWw/HEyn6AQKBgQDwOFYmOb31/tbv6iyR
P2f0nHPiAY5Q29K2fr3k+TMEAJ3Ados7/bbGa9Vgcdk1AkiZyYA2xBTC7AZmVQs/
9SpPPlSwfBgorgn/vK9HTWv/n91YOK4TUt3+lgrtvGgpDaaJWjSAKGP2D8au9/cJ
4Dcr1j7PhSNW0qMaOKpnOsttQQKBgQDbnSzHptddmzu0Ctxf0JusN55NApdbFrk1
BlDP3g6v6YEMnRIWIV4KaQtuqw9aSSRqzstn+Z+GowcJ4YI6DvcI0jE+mLT1HJb+
tHnqD/GgeqsKwmps68cUD1tGORudrrUdMWf+d5C/8jlM9eCnWI/0tISBJjVi/f3b
NL4ZcrYDWQKBgBNluS8lAn3Wsix1UFv6Lr7F02WwknldBsrNuS/AH6p3EkX0TJHv
js6+7l/3UX7CTHJ+nufNNY/31xx0SZBEj8IOWnBV1O2UACKybcToL4xYsFrrWMMe
seZY31ELIa4O+B+nNQ4UNN4tr/F4/G3DuTDFABVpvszH/Xukj73+NWcBAoGBAL/V
kMspixDCS6menxe3InSR9N5yOAIiXE/cH3UkFJJHFyoMfkMEjJ/tWEYoeHW2VHBU
CUveuiGigMB50waiEdoLuWZjgBZoDeGZhrEVkkxLOuNgJhTU9AYqz+EMe3oGpUBF
6wBWMwPoM3Nth/rGGqF3mhMybAn3sersLG4QTLupAoGARFBOyipPPU3/m6RC2N42
pupQCbrAlaBoEVmMJSfttpKXMyqPRxZbH4DY2Q4xbVQprrHUGPe1wpeka60ru39v
qS9TI+WZLC5+5mdfykkDC74cvQ4BL68zhnlbYjCOc+w7HahLsKo/aYK/V0y2xLcA
McZj8FUA23o/8fUvjeSH+ww=
-----END PRIVATE KEY-----
"#;
