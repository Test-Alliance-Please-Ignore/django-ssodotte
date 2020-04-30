OIDC_OP_AUTHORIZATION_ENDPOINT = "https://sso.pleaseignore.com/auth/realms/auth-ng/protocol/openid-connect/auth"
OIDC_OP_TOKEN_ENDPOINT = "https://sso.pleaseignore.com/auth/realms/auth-ng/protocol/openid-connect/token"
OIDC_OP_USER_ENDPOINT = "https://sso.pleaseignore.com/auth/realms/auth-ng/protocol/openid-connect/userinfo"

OIDC_RP_SIGN_ALGO = 'RS256'

OIDC_RP_SCOPES = "openid"

# This is derived from https://sso.pleaseignore.com/auth/realms/auth-ng/protocol/openid-connect/certs
OIDC_RP_IDP_SIGN_KEY = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAqraRVf6zYu6k05Ml22xsUsUOZsmJP4Cqtq4CWut2HGwFFY49BmOV
VFVNnOkGQWVc4NDtjwEWfiel71QWrrHHyfiHNfRDvg4mnbTmAg9b+M8mdy02Ulvt
NwtqwYuUJnHgsMW+pPFZMOggmE28cANu5yrr0OFSjqC5Z6PAPOSJepOjSkkvRXNI
JcLHLxkCRpPCT+Osz+L4Z0MaHt3BqZ5y43KhopiPjrCXsVU4hcRncJIsFK2zutGY
RRWlTh5De5lxqxBr1e/7RbxOt/j/5nDySrJE8d6Dilx+fxGkM/tBCoR5ARR9NdKM
Cf0BjvqTpCIYp9CWnhTFqK5FldYiG+twAQIDAQAB
-----END RSA PUBLIC KEY-----"""
