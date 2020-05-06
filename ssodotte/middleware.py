import logging
import time

from django.contrib.auth import BACKEND_SESSION_KEY
from django.utils.module_loading import import_string
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.middleware import SessionRefresh
from mozilla_django_oidc.utils import import_from_settings, is_authenticated


LOGGER = logging.getLogger(__name__)


class TokenRefresh(SessionRefresh):
    """
    Refreshes access and ID tokens after expiration.

    For users authenticated with the OIDC RP, verify tokens are still valid and
    if not, refresh tokens without user interruption.

    """

    auth_backend = None

    def is_refreshable_url(self, request):
        """
        Takes a request and returns whether it triggers a refresh examination

        :arg HttpRequest request:

        :returns: boolean

        """
        # Do not attempt to refresh the session if the OIDC backend is not used
        backend_session = request.session.get(BACKEND_SESSION_KEY)
        is_oidc_enabled = False
        if backend_session:
            self.auth_backend = import_string(backend_session)
            is_oidc_enabled = issubclass(self.auth_backend, OIDCAuthenticationBackend)

        return (
            # unlike SessionRefresh, don't check request method
            is_authenticated(request.user)
            and is_oidc_enabled
            and request.path not in self.exempt_urls
        )

    def process_request(self, request):
        if not self.is_refreshable_url(request):
            LOGGER.debug("request is not refreshable")
            return

        LOGGER.debug("checking tokens")
        now = time.time() + 15  # add 15s, so we don't expire while making a call
        refresh_token_expiration = request.session.get(
            "oidc_refresh_token_expiration", 0
        )
        access_token_expiration = request.session.get("oidc_access_token_expiration", 0)

        if (
            import_from_settings("OIDC_STORE_REFRESH_TOKENS", False)
            and access_token_expiration < now < refresh_token_expiration
        ):
            # try to refresh expired tokens with refresh token
            LOGGER.debug(
                "tokens invalid, refreshing tokens, %s",
                [access_token_expiration - now, refresh_token_expiration - now,],
            )

            token_payload = {
                "grant_type": "refresh_token",
                "refresh_token": request.session["oidc_refresh_token"],
                "client_id": import_from_settings("OIDC_RP_CLIENT_ID"),
                "client_secret": import_from_settings("OIDC_RP_CLIENT_SECRET"),
            }

            # also stores the new tokens, no need to do anything else
            # need to instantiate the backend first
            auth = self.auth_backend()
            auth.get_tokens(request.session, token_payload)

        else:
            # The access token is still valid, so we don't have to do anything.
            LOGGER.debug(
                "tokens are still valid, not auto refreshing, (%s, %s > %s)",
                refresh_token_expiration,
                access_token_expiration,
                now,
            )
