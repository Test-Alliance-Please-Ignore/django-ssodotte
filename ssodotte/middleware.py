import logging
import time
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.utils.crypto import get_random_string
from mozilla_django_oidc.middleware import SessionRefresh
from mozilla_django_oidc.utils import (
    absolutify,
    import_from_settings
)
from sentinel import auth
from urllib.parse import urlencode

LOGGER = logging.getLogger(__name__)


class AutoSessionRefresh(SessionRefresh):
    """Refreshes the session with the OIDC RP after expiry seconds

    For users authenticated with the OIDC RP, verify tokens are still valid and
    if not, force the user to re-authenticate silently.

    """

    def process_request(self, request):
        if not self.is_refreshable_url(request):
            LOGGER.debug('request is not refreshable')
            return

        refresh_token_expiration = request.session.get('oidc_refresh_token_expiration', 0)
        access_token_expiration = request.session.get('oidc_access_token_expiration', 0)
        id_token_expiration = request.session.get('oidc_id_token_expiration', 0)

        now = time.time() + 15  # add 15s, so we don't expire while making a call

        LOGGER.debug('checking tokens, ' + str(request.session.keys()))

        if import_from_settings('OIDC_AUTO_REFRESH_TOKENS', False) \
                and refresh_token_expiration > now \
                and (access_token_expiration < now or id_token_expiration < now):
            # try to refresh expired tokens with refresh token
            LOGGER.debug('tokens invalid, refreshing tokens')

            token_payload = {
                'grant_type': 'refresh_token',
                'refresh_token': request.session['oidc_refresh_token'],
                'client_id': import_from_settings('OIDC_RP_CLIENT_ID'),
                'client_secret': import_from_settings('OIDC_RP_CLIENT_SECRET'),
            }
            token_info = auth.get_tokens(token_payload)
            auth.store_tokens(request.session, token_info)
            return

        elif id_token_expiration > now:
            # The id_token is still valid, so we don't have to do anything.
            # ID token will expire before refresh token, so no need to check for that
            LOGGER.debug('id token is still valid (%s > %s)', id_token_expiration, now)
            return

        LOGGER.debug('id token has expired')
        # The id_token has expired, so we have to re-authenticate silently.
        auth_url = import_from_settings('OIDC_OP_AUTHORIZATION_ENDPOINT')
        client_id = import_from_settings('OIDC_RP_CLIENT_ID')
        state = get_random_string(import_from_settings('OIDC_STATE_SIZE', 32))

        # Build the parameters as if we were doing a real auth handoff, except
        # we also include prompt=none.
        params = {
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': absolutify(
                request,
                reverse('oidc_authentication_callback')
            ),
            'state': state,
            'scope': import_from_settings('OIDC_RP_SCOPES', 'openid email'),
            'prompt': 'none',
        }

        if import_from_settings('OIDC_USE_NONCE', True):
            nonce = get_random_string(import_from_settings('OIDC_NONCE_SIZE', 32))
            params.update({
                'nonce': nonce
            })
            request.session['oidc_nonce'] = nonce

        request.session['oidc_state'] = state
        request.session['oidc_login_next'] = request.get_full_path()

        query = urlencode(params)
        redirect_url = '{url}?{query}'.format(url=auth_url, query=query)
        if request.is_ajax():
            # Almost all XHR request handling in client-side code struggles
            # with redirects since redirecting to a page where the user
            # is supposed to do something is extremely unlikely to work
            # in an XHR request. Make a special response for these kinds
            # of requests.
            # The use of 403 Forbidden is to match the fact that this
            # middleware doesn't really want the user in if they don't
            # refresh their session.
            response = JsonResponse({'refresh_url': redirect_url}, status=403)
            response['refresh_url'] = redirect_url
            return response
        return HttpResponseRedirect(redirect_url)
