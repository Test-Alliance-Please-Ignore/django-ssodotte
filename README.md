# django-ssodotte

This is essentially a super thin wrapper around `mozilla-django-oidc`. It does
some configuration for you and it defines a very, very basic custom
authentication backend that handles some of the differences between what
ssodotte provides and what `mozilla-django-oidc` expects. If you don't want to
use this wrapper you can look in the `ssodotte/config.py` file for the config
you need and you can check `ssodotte/auth.py` to get an idea of what your auth
backend should look like.

## Writing _ssodotte_ applications in Django

So you want to write a Django application that uses the new TEST authentication
method called _ssodotte_? Good choice. It's surprisingly simple and hopefully
this document will guide you through the process of setting up your own
ssodotte-powered application!

### Creating a virtual environment

First things first lets setup out virtual environment. In this guide I'm using
the following config but you are free to do whatever you want:

    $ mkvirtualenv --python=$(which python3.6) ssodotte_test
    $ workon ssodotte_test

We will also install some prerequisites:

    $ pip install django
    $ pip install git+ssh://git@cicd.pleaseignore.com:2022/test-it/django-ssodotte.git

### Creating a Django project

This is largely the same as in any other Django project and the official docs
will do a much better job at explaining it than I ever could. One thing to note
is that in my experience a fresh virtual environment doesn't always have the
binary path set up correctly, so I like to check that the `django-admin`
command is indeed the right one:

    $ which django-admin
    /home/stephen/.virtualenvs/ssodotte/bin/django-admin

Then, we create the Django project:

    $ djang-admin startproject ssodotte_test

There are quite a few things that I don't like about the standard Django setup,
especially the way settings are implemented, but that is outside the scope of
this guide.

We can test that our Django project works by running the server:

    $ python manage.py migrate
    $ python manage.py runserver

### Installing the ssodotte app

At the top of your settings file, put the following line:

    from ssodotte.config import *

Then, add `'ssodotte'` to your installed apps, and use the following auth
backends:

    AUTHENTICATION_BACKENDS = (
        'django.contrib.auth.backends.ModelBackend',
        'ssodotte.auth.SsodotteBackend',
    )

Finally, go into your URLs and add the following path:

    path('ssodotte/', include('ssodotte.urls')),

### Retrieving a ssodotte client ID and secret

If you need to know only if someone is in TEST or not (which, let's be real
here, is probably all you need) you can easily create your own ssodotte client.
If you need more scopes, you will need to call a madmin.

We'll start up a Python shell and request a client ID and secret from the
OIDC provider:

    >>> import requests
    >>> import pprint
    >>> DATA = {'name': 'ssodotte for dummies', 'redirectUris': ['http://127.0.0.1:8000/ssodotte/callback/']}
    >>> r = requests.post('https://sso.pleaseignore.com/auth/realms/auth-ng/clients-registrations/default/', json=DATA)
    >>> pprint.pprint(r.json())
    {'attributes': {},
    'bearerOnly': False,
    'clientAuthenticatorType': 'client-secret',
    'clientId': '...',
    'consentRequired': True,
    'directAccessGrantsEnabled': False,
    'enabled': True,
    'frontchannelLogout': False,
    'fullScopeAllowed': True,
    'id': '...',
    'implicitFlowEnabled': False,
    'name': 'ssodotte for dummies',
    'nodeReRegistrationTimeout': -1,
    'notBefore': 0,
    'publicClient': False,
    'redirectUris': ['http://127.0.0.1:8000/ssodotte/callback/'],
    'registrationAccessToken': '...',
    'secret': '...',
    'serviceAccountsEnabled': False,
    'standardFlowEnabled': True,
    'surrogateAuthRequired': False,
    'useTemplateConfig': False,
    'useTemplateMappers': False,
    'useTemplateScope': False,
    'webOrigins': ['http://127.0.0.1:8000']}

We're specifically interested in the `id` and `secret` values. Keep them for
the next step!

### Adding your ID and secret

Create two final settings in your Django configuration and insert the correct
values:

    OIDC_RP_CLIENT_ID = 'your-id-here'
    OIDC_RP_CLIENT_SECRET = 'me-too-thanks'

### Writing views

That's it! You can now write views using the standard Django user model (and
possibly your custom model too)! The login URL can be found under the name
`ssodotte:login` and the URL to log out is `ssodotte:logout`.

### Troubleshooting

There's some errors that you might encounter if you were a dumb.

#### "Invalid parameter: redirect_uri"

This probably means you didn't add a trailing slash to your callback URI when
you requested your client.

#### SessionRefresh and refreshing tokens

In addition to [SessionRefresh](https://mozilla-django-oidc.readthedocs.io/en/stable/installation.html#validate-id-tokens-by-renewing-them),
included in mozilla-oidc, `TokenRefresh` is included in this to refresh tokens within requests when they expire,
without redirecting users. To use these middleware, simply add them to the django settings:

    MIDDLEWARE += [
        # middleware involving session and authentication must come first
        # ...
        'ssodotte.middleware.TokenRefresh',
        'mozilla_django_oidc.middleware.SessionRefresh'  # add this after token refresh, otherwise you may redirect your users
        # ...
    ]

Other important settings, only `OIDC_STORE_REFRESH_TOKENS` is unique to ssodotte:

    OIDC_STORE_ACCESS_TOKEN = True
    OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS = 15 * 60  # expiry for ID tokens, used in both middleware
    OIDC_EXEMPT_URLS = []  # URLs exempt from both middleware
    OIDC_STORE_REFRESH_TOKENS = True  # Required for TokenRefresh to function, enables saving refresh token and token expiries
