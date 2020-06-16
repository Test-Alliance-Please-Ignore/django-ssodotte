import logging
import time
import json

from requests import RequestException
from django.contrib.auth import BACKEND_SESSION_KEY, load_backend, logout, login
from django.core.exceptions import SuspiciousOperation
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.middleware import SessionRefresh
from mozilla_django_oidc.utils import import_from_settings, is_authenticated
from josepy.b64 import b64decode


LOGGER = logging.getLogger(__name__)


class TokenRefreshMiddleware(SessionRefresh):
    """
    Refreshes access and ID tokens after expiration.

    For users authenticated with the OIDC RP, verify tokens are still valid and
    if not, refresh tokens without user interruption.

    """

    def get_backend_instance(self, backend_path):
        if not backend_path:
            return None

        return load_backend(backend_path)

    def is_refreshable_url(self, request, backend):
        """
        Takes a request and returns whether it triggers a refresh examination

        :arg HttpRequest request:

        :returns: boolean

        """
        # Do not attempt to refresh the session if the OIDC backend is not used
        if not isinstance(backend, OIDCAuthenticationBackend):
            return False

        return (
            # unlike SessionRefresh, don't check request method
            is_authenticated(request.user)
            and request.path not in self.exempt_urls
        )

    def get_jwt_payload_no_validation(self, token):
        payload_data = token.split(".")[1]
        return json.loads(b64decode(payload_data))

    def process_request(self, request):
        if not import_from_settings("OIDC_STORE_REFRESH_TOKENS", False):
            LOGGER.debug("OIDC_STORE_REFRESH_TOKENS isn't on")
            return

        backend_path = request.session.get(BACKEND_SESSION_KEY)
        backend = self.get_backend_instance(backend_path)

        if not self.is_refreshable_url(request, backend):
            LOGGER.debug("request is not refreshable")
            return

        LOGGER.debug("checking tokens")
        now = time.time() + 15  # add 15s, so we don't expire while making a call
        refresh_token_expiration = request.session.get(
            "oidc_refresh_token_expiration", 0
        )
        access_token_expiration = request.session.get("oidc_access_token_expiration", 0)

        # Log the user out if the refresh token is expired (we can't refresh
        # their token)
        if now >= refresh_token_expiration:
            logout(request)
            return

        if access_token_expiration < now < refresh_token_expiration:
            # try to refresh expired access token with refresh token
            LOGGER.debug(
                "access token expired, refreshing. token expiries: %s",
                [access_token_expiration - now, refresh_token_expiration - now],
            )

            token_payload = {
                "grant_type": "refresh_token",
                "refresh_token": request.session["oidc_refresh_token"],
                "client_id": import_from_settings("OIDC_RP_CLIENT_ID"),
                "client_secret": import_from_settings("OIDC_RP_CLIENT_SECRET"),
            }

            # Call the OIDCAuthenticationBackend to get/store the new tokens
            # and validate access
            backend.request = request
            try:
                token_info = backend.get_token(token_payload)
            except RequestException:
                LOGGER.warning("Could not refresh token", exc_info=True)
                logout(request)
                return

            id_token = token_info.get("id_token")
            access_token = token_info.get("access_token")

            # We can't actually check the nonce here (it's the same as the one
            # used on initial login), so just fetch the nonce in the token and
            # cause the comparison to be a no-op
            nonce = self.get_jwt_payload_no_validation(id_token).get("nonce")
            payload = backend.verify_token(id_token, nonce=nonce)

            user = None
            if payload:
                backend.store_tokens(access_token, id_token)
                try:
                    user = backend.get_or_create_user(access_token, id_token, payload)
                except SuspiciousOperation:
                    LOGGER.warning(
                        "Could not get or create user during token refresh",
                        exc_info=True,
                    )

            if not user or request.user.id != user.id:
                logout(request)
        else:
            # The access token is still valid, so we don't have to do anything.
            LOGGER.debug(
                "tokens are still valid, not auto refreshing, (%s, %s > %s)",
                refresh_token_expiration,
                access_token_expiration,
                now,
            )
