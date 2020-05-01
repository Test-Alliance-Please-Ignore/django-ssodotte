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
        sub_id = claims.get('sub')

        if not sub_id:
            return self.UserModel.objects.none()

        return self.UserModel.objects.filter(username=sub_id)

    def verify_claims(self, claims):
        """Verify the provided claims to decide if authentication should be allowed."""
        return "sub" in claims

    def create_user(self, claims):
        sub_id = claims.get('sub')

        if not sub_id:
            raise ValueError('No subject ID found in claim')

        return self.UserModel.objects.create_user(sub_id)

    def get_username(self, claims):
        # this method is only used in create_user, but we overrode that, so it should be unused.
        raise Exception('This should not have been called, something went wrong. mozilla-django-oidc probably updated and broke something')

    def authenticate(self, request, **kwargs):
        """Authenticates a user based on the OIDC code flow."""
        LOGGER.debug('authenticating')

        self.request = request
        if not self.request:
            return None

        state = self.request.GET.get('state')
        code = self.request.GET.get('code')
        nonce = kwargs.pop('nonce', None)

        if not code or not state:
            return None

        reverse_url = import_from_settings('OIDC_AUTHENTICATION_CALLBACK_URL',
                                           'oidc_authentication_callback')

        token_payload = {
            'client_id': self.OIDC_RP_CLIENT_ID,
            'client_secret': self.OIDC_RP_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': absolutify(
                self.request,
                reverse(reverse_url)
            ),
        }

        # Get the token
        token_info = get_tokens(token_payload)
        id_token = token_info.get('id_token')
        access_token = token_info.get('access_token')

        # Validate the token
        payload = self.verify_token(id_token, nonce=nonce)

        if payload:
            store_tokens(self.request.session, token_info)
            try:
                return self.get_or_create_user(access_token, id_token, payload)
            except SuspiciousOperation as exc:
                LOGGER.warning('failed to get or create user: %s', exc)
                return None

        return None


def get_tokens(payload):
    """Return token object as a dictionary."""

    auth = None
    if import_from_settings('OIDC_TOKEN_USE_BASIC_AUTH', False):
        # When Basic auth is defined, create the Auth Header and remove secret from payload.
        user = payload.get('client_id')
        pw = payload.get('client_secret')

        auth = HTTPBasicAuth(user, pw)
        del payload['client_secret']

    response = requests.post(
        import_from_settings('OIDC_OP_TOKEN_ENDPOINT'),
        data=payload,
        auth=auth,
        verify=import_from_settings('OIDC_VERIFY_SSL', True))
    response.raise_for_status()
    return response.json()


def store_tokens(session, token_info):
    """Store OIDC tokens."""

    if import_from_settings('OIDC_AUTO_REFRESH_TOKENS', False):
        LOGGER.debug('storing refresh tokens' + str([token_info.get('refresh_expires_in'),token_info.get('expires_in')]))
        session['oidc_refresh_token'] = token_info.get('refresh_token')
        session['oidc_refresh_token_expiration'] = math.floor(time.time() + token_info.get('refresh_expires_in'))
        session['oidc_access_token_expiration'] = math.floor(time.time() + token_info.get('expires_in'))
        LOGGER.debug('tokens stored, ' + str(session.keys()))

    if import_from_settings('OIDC_STORE_ACCESS_TOKEN', False):
        session['oidc_access_token'] = token_info.get('access_token')

    if import_from_settings('OIDC_STORE_ID_TOKEN', False):
        session['oidc_id_token'] = token_info.get('id_token')
