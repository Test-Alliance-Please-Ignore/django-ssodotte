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
        """
        Verify the provided claims to decide if authentication should be allowed.
        """
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
        """
        Return token object as a dictionary.
        """
        token_info = super(SsodotteBackend, self).get_token(payload)

        if import_from_settings("OIDC_STORE_REFRESH_TOKENS", False):
            LOGGER.debug(
                "storing refresh tokens, %s",
                [token_info.get("refresh_expires_in"), token_info.get("expires_in")],
            )
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

        return token_info
