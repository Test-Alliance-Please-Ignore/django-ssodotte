import json
import logging
import math
import requests
import time
from django.core.exceptions import SuspiciousOperation
from django.urls import reverse
from django.utils.encoding import force_bytes
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

    def get_token(self, payload, request=None):
        """
        Return token object as a dictionary.
        """
        token_info = super(SsodotteBackend, self).get_token(payload)

        # no token verification needed if we aren't using the TokenRefreshMiddleware,
        # token verification happens in authenticate anyways
        if not import_from_settings("OIDC_STORE_REFRESH_TOKENS", False):
            return token_info

        id_token = token_info.get("id_token")
        access_token = token_info.get("access_token")

        token = force_bytes(id_token)
        if self.OIDC_RP_SIGN_ALGO.startswith("RS"):
            if self.OIDC_RP_IDP_SIGN_KEY is not None:
                key = self.OIDC_RP_IDP_SIGN_KEY
            else:
                key = self.retrieve_matching_jwk(token)
        else:
            key = self.OIDC_RP_CLIENT_SECRET

        payload_data = self.get_payload_data(token, key)
        payload = json.loads(payload_data.decode("utf-8"))
        token_nonce = payload.get("nonce")

        # Validate the token
        payload = self.verify_token(id_token, nonce=token_nonce)
        LOGGER.debug("verified, %s", payload)

        # only set tokens if we have a valid payload
        if payload:
            # we don't call store_tokens here, since they will be stored later anyway
            # access tokens will still be stored below for TokenRefreshMiddleware use

            LOGGER.debug("stored tokens")
            try:
                user = self.get_or_create_user(
                    access_token, id_token, payload
                )  # we should already have a user
                LOGGER.debug("get/create user, %s", user)
            except SuspiciousOperation as exc:
                LOGGER.warning("failed to get or create user: %s", exc)
                raise exc

            session = request.session if request else self.request.session
            LOGGER.debug("session exists, %s", session)

            # set tokens after we verifying them
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

            # access tokens are stored in stored_tokens as well, but needs to be done here for TokenRefreshMiddleware
            if import_from_settings("OIDC_STORE_ACCESS_TOKEN", False):
                session["oidc_access_token"] = token_info.get("access_token")

        return (
            token_info  # always return token_info, since, it was always returned anyway
        )
