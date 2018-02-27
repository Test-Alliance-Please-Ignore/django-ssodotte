from django.contrib.auth import get_user_model

from mozilla_django_oidc.auth import OIDCAuthenticationBackend

from ssodotte import config


class SsodotteBackend(OIDCAuthenticationBackend):
    def filter_users_by_claims(self, claims):
        sub_id = claims.get('sub')

        if not sub_id:
            return self.UserModel.objects.none()

        return self.UserModel.objects.filter(username=sub_id)


    def create_user(self, claims):
        sub_id = claims.get('sub')

        if not sub_id:
            raise ValueError('No subject ID found in claim')

        return self.UserModel.objects.create_user(sub_id)
