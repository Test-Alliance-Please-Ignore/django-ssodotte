from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.utils import import_from_settings


class SsodotteBackend(OIDCAuthenticationBackend):
    def filter_users_by_claims(self, claims):
        sub_id = claims.get('sub')

        if not sub_id:
            return self.UserModel.objects.none()

        return self.UserModel.objects.filter(username=sub_id)

    def verify_claims(self, claims):
        """Verify the provided claims to decide if authentication should be allowed."""

        scopes = import_from_settings('OIDC_RP_SCOPES', 'openid sub')

        # yes, we really are checking against a string two lines above, since the setting is not set
        if 'sub' in scopes.split():
            return 'sub' in claims

        return True  # yes this really is the default

    def create_user(self, claims):
        sub_id = claims.get('sub')

        if not sub_id:
            raise ValueError('No subject ID found in claim')

        return self.UserModel.objects.create_user(sub_id)

    def get_username(self, claims):
        # this method is only used in create_user, but we overrode that, so it should be unused.
        raise Exception('This should not have been called, something went wrong. mozilla-django-oidc probably updated and broke something')