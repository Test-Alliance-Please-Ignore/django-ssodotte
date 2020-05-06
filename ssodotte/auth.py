import logging
import math
import requests
import time
from django.core.exceptions import SuspiciousOperation
from django.urls import reverse
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.utils import absolutify, import_from_settings
from requests.auth import HTTPBasicAuth

LOGGER = logging.getLogger(__name__)


class SsodotteBackend(OIDCAuthenticationBackend):
    def filter_users_by_claims(self, claims):
        sub_id = claims.get("sub")

        if not sub_id:
            return self.UserModel.objects.none()

        return self.UserModel.objects.filter(username=sub_id)

    def verify_claims(self, claims):
        """Verify the provided claims to decide if authentication should be allowed."""
        return "sub" in claims

    def create_user(self, claims):
        sub_id = claims.get("sub")

        if not sub_id:
            raise ValueError("No subject ID found in claim")

        return self.UserModel.objects.create_user(sub_id)

    def get_username(self, claims):
        # this method is only used in create_user, but we overrode that, so it should be unused.
        raise Exception(
            "This should not have been called, something went wrong. mozilla-django-oidc probably updated and broke something"
        )

    def get_token(self, payload):
        return get_tokens(self.request.session, payload)


def get_tokens(session, payload):
    """Return token object as a dictionary."""

    auth = None
    if import_from_settings("OIDC_TOKEN_USE_BASIC_AUTH", False):
        # When Basic auth is defined, create the Auth Header and remove secret from payload.
        user = payload.get("client_id")
        pw = payload.get("client_secret")

        auth = HTTPBasicAuth(user, pw)
        del payload["client_secret"]

    response = requests.post(
        import_from_settings("OIDC_OP_TOKEN_ENDPOINT"),
        data=payload,
        auth=auth,
        verify=import_from_settings("OIDC_VERIFY_SSL", True),
    )
    response.raise_for_status()
    token_info = response.json()

    if import_from_settings("OIDC_AUTO_REFRESH_TOKENS", False):
        LOGGER.debug(
            "storing refresh tokens"
            + str([token_info.get("refresh_expires_in"), token_info.get("expires_in")])
        )
        expiration_interval = import_from_settings(
            "OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS", 60 * 15
        )
        session["oidc_id_token_expiration"] = time.time() + expiration_interval
        session["oidc_refresh_token"] = token_info.get("refresh_token")
        session["oidc_refresh_token_expiration"] = math.floor(
            time.time() + token_info.get("refresh_expires_in")
        )
        session["oidc_access_token_expiration"] = math.floor(
            time.time() + token_info.get("expires_in")
        )
        LOGGER.debug("tokens stored, " + str(session.keys()))

    if import_from_settings("OIDC_STORE_ACCESS_TOKEN", False):
        session["oidc_access_token"] = token_info.get("access_token")

    if import_from_settings("OIDC_STORE_ID_TOKEN", False):
        session["oidc_id_token"] = token_info.get("id_token")

    return token_info
