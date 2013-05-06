""" Module defining the Django auth backend class for the Keystone API. """

import abc
import hashlib
import logging

from django.conf import settings
from django.utils.translation import ugettext_lazy as _

from keystoneclient import exceptions as keystone_exceptions
from keystoneclient.v2_0.tokens import Token, TokenManager

from .exceptions import KeystoneAuthException
from .user import create_user_from_token
from .utils import check_token_expiration, is_ans1_token


LOG = logging.getLogger(__name__)


KEYSTONE_CLIENT_ATTR = "_keystoneclient"


class KeystoneBackend(object):

    keystone = None

    def __init__(self):
        self.keystone = KeystoneManager.factory()

    @property
    def request(self):
        return self.keystone.request

    @request.setter
    def request(self, value):
        self.keystone.request = value

    def check_auth_expiry(self, accessInfo):
        return self.keystone.check_auth_expiry(accessInfo=accessInfo)

    def get_user(self, user_id):
        return self.keystone.get_user(user_id=user_id)

    def authenticate(self, **kwargs):
        return self.keystone.authenticate(**kwargs)

    def get_group_permissions(self, user, obj=None):
        return self.keystone.get_group_permissions(user=user, obj=obj)

    def get_all_permissions(self, user, obj=None):
        return self.keystone.get_all_permissions(user=user, obj=obj)

    def has_perm(self, user, perm, obj=None):
        return self.keystone.has_perm(user=user, perm=perm, obj=obj)

    def has_module_perms(self, user, app_label):
        return self.keystone.has_module_perms(user=user, app_label=app_label)


class KeystoneManager(object):
    """
    Django authentication backend class for use with ``django.contrib.auth``.
    """

    __metaclass__ = abc.ABCMeta

    @classmethod
    def factory(cls):
        """
        Create Keystone object given the arguments.
        """
        if KeystoneV3.isValid():
            return KeystoneV3()
        elif KeystoneV2.isValid():
            return KeystoneV2()
        else:
            raise NotImplementedError('Keystone version could not '
                                      'be identified.')

    @classmethod
    def version(cls):
        if KeystoneV3.isValid():
            return 3
        elif KeystoneV2.isValid():
            return 2
        else:
            raise NotImplementedError('Keystone version could not '
                                      'be identified.')

    @abc.abstractmethod
    def get_client(self):
        raise NotImplementedError()

    def check_auth_expiry(self, token):
        if not check_token_expiration(token):
            msg = _("The authentication token issued by the Identity service "
                    "has expired.")
            LOG.warning("The authentication token issued by the Identity "
                        "service appears to have expired before it was "
                        "issued. This may indicate a problem with either your "
                        "server or client configuration.")
            raise KeystoneAuthException(msg)
        return True

    @abc.abstractmethod
    def get_user(self, user_id):
        """
        Returns the current user (if authenticated) based on the user ID
        and session data.

        Note: this required monkey-patching the ``contrib.auth`` middleware
        to make the ``request`` object available to the auth backend class.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def authenticate(self, **kwargs):
        """ Authenticates a user via the Keystone Identity API. """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_group_permissions(self, user, obj=None):
        """ Returns an empty set since Keystone doesn't support "groups". """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_all_permissions(self, user, obj=None):
        """
        Returns a set of permission strings that this user has through his/her
        Keystone "roles".

        The permissions are returned as ``"openstack.{{ role.name }}"``.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def has_perm(self, user, perm, obj=None):
        """ Returns True if the given user has the specified permission. """
        raise NotImplementedError()

    @abc.abstractmethod
    def has_module_perms(self, user, app_label):
        """
        Returns True if user has any permissions in the given app_label.

        Currently this matches for the app_label ``"openstack"``.
        """
        raise NotImplementedError()


class KeystoneV2(KeystoneManager):

    @classmethod
    def isValid(cls):
        key = getattr(settings, 'OPENSTACK_API_VERSIONS', {}).get('identity')
        return key < 3

    def get_client(self):
        from keystoneclient.v2_0 import client
        return client

    def get_user(self, user_id):
        if user_id == self.request.session["user_id"]:
            token = Token(TokenManager(None),
                          self.request.session['token'],
                          loaded=True)
            endpoint = self.request.session['region_endpoint']
            return create_user_from_token(self.request, token, endpoint)
        else:
            return None

    def authenticate(self, request=None, username=None, password=None,
                     tenant=None, auth_url=None):
        LOG.debug('Beginning user V2 authentication for user "%s".' % username)

        insecure = getattr(settings, 'OPENSTACK_SSL_NO_VERIFY', False)

        try:
            client = self.get_client().Client(username=username,
                                              password=password,
                                              tenant_id=tenant,
                                              auth_url=auth_url,
                                              insecure=insecure)
            unscoped_token_data = {"token": client.service_catalog.get_token()}
            unscoped_token = Token(TokenManager(None),
                                   unscoped_token_data,
                                   loaded=True)
        except (keystone_exceptions.Unauthorized,
                keystone_exceptions.Forbidden,
                keystone_exceptions.NotFound) as exc:
            msg = _('Invalid user name or password.')
            LOG.debug(exc.message)
            raise KeystoneAuthException(msg)
        except (keystone_exceptions.ClientException,
                keystone_exceptions.AuthorizationFailure) as exc:
            msg = _("An error occurred authenticating. "
                    "Please try again later.")
            LOG.debug(exc.message)
            raise KeystoneAuthException(msg)

        # Check expiry for our unscoped token.
        self.check_auth_expiry(unscoped_token)

        # FIXME: Log in to default tenant when the Keystone API returns it...
        # For now we list all the user's tenants and iterate through.
        try:
            tenants = client.tenants.list()
        except (keystone_exceptions.ClientException,
                keystone_exceptions.AuthorizationFailure):
            msg = _('Unable to retrieve authorized projects.')
            raise KeystoneAuthException(msg)

        # Abort if there are no tenants for this user
        if not tenants:
            msg = _('You are not authorized for any projects.')
            raise KeystoneAuthException(msg)

        while tenants:
            tenant = tenants.pop()
            try:
                client = self.get_client().Client(tenant_id=tenant.id,
                                                  token=unscoped_token.id,
                                                  auth_url=auth_url,
                                                  insecure=insecure)
                token = client.tokens.authenticate(username=username,
                                                   token=unscoped_token.id,
                                                   tenant_id=tenant.id)
                break
            except (keystone_exceptions.ClientException,
                    keystone_exceptions.AuthorizationFailure):
                token = None

        if token is None:
            msg = _("Unable to authenticate to any available projects.")
            raise KeystoneAuthException(msg)

        # Check expiry for our new scoped token.
        self.check_auth_expiry(token)

        # If we made it here we succeeded. Create our User!
        user = create_user_from_token(request,
                                      token,
                                      client.service_catalog.url_for())

        if request is not None:
            if is_ans1_token(unscoped_token.id):
                hashed_token = hashlib.md5(unscoped_token.id).hexdigest()
                unscoped_token._info['token']['id'] = hashed_token
            request.session['unscoped_token'] = unscoped_token.id
            request.user = user

            # Support client caching to save on auth calls.
            setattr(request, KEYSTONE_CLIENT_ATTR, client)

        LOG.debug('Authentication completed for user "%s".' % username)
        return user

    def get_group_permissions(self, user, obj=None):
        return set()

    def get_all_permissions(self, user, obj=None):
        if user.is_anonymous() or obj is not None:
            return set()
        # TODO: Integrate policy-driven RBAC when supported by Keystone.
        role_perms = set(["openstack.roles.%s" % role['name'].lower()
                          for role in user.roles])
        service_perms = set(["openstack.services.%s" % service['type'].lower()
                          for service in user.service_catalog])
        return role_perms | service_perms

    def has_perm(self, user, perm, obj=None):
        if not user.is_active:
            return False
        return perm in self.get_all_permissions(user, obj)

    def has_module_perms(self, user, app_label):
        if not user.is_active:
            return False
        for perm in self.get_all_permissions(user):
            if perm[:perm.index('.')] == app_label:
                return True
        return False


class KeystoneV3(KeystoneManager):

    @classmethod
    def isValid(cls):
        key = getattr(settings, 'OPENSTACK_API_VERSIONS', {}).get('identity')
        return key == 3

    def get_client(self):
        from keystoneclient.v3 import client
        return client

    def get_user(self, user_id):
        if user_id == self.request.session["user_id"]:
            token = self.request.session['token']
            #token = Token(TokenManager(None),
            #              self.request.session['token'],
            #              loaded=True)
            endpoint = self.request.session['region_endpoint']
            return create_user_from_token(self.request, token, endpoint)
        else:
            return None

    def authenticate(self, request=None, username=None, password=None,
                     domain=None, tenant=None, auth_url=None):
        LOG.debug('Beginning user V3 authentication for user "%s".' % username)

        insecure = getattr(settings, 'OPENSTACK_SSL_NO_VERIFY', False)

        try:
            domain = 'Default'
            client = self.get_client().Client(username=username,
                                              password=password,
                                              user_domain_name=domain,
                                              auth_url=auth_url,
                                              insecure=insecure,
                                              debug=True)
            client.management_url = auth_url
            #unscoped_token_data = {"token": client.service_catalog.get_token()}
            #unscoped_token = Token(TokenManager(None),
            #                       unscoped_token_data,
            #                       loaded=True)
            unscoped_token = client.auth_ref
        except (keystone_exceptions.Unauthorized,
                keystone_exceptions.Forbidden,
                keystone_exceptions.NotFound) as exc:
            msg = _('Invalid user name or password.')
            LOG.debug(exc.message)
            raise KeystoneAuthException(msg)
        except (keystone_exceptions.ClientException,
                keystone_exceptions.AuthorizationFailure) as exc:
            import traceback
            import sys
            traceback.print_exc(file=sys.stdout)
            msg = _("An error occurred authenticating. "
                    "Please try again later.")
            LOG.debug(exc.message)
            raise KeystoneAuthException(msg)

        # Check expiry for our unscoped token.
        self.check_auth_expiry(unscoped_token)

        # FIXME: Log in to default tenant when the Keystone API returns it...
        # For now we list all the user's tenants and iterate through.
        try:
            tenants = client.projects.list(user=unscoped_token.user_id)
        except (keystone_exceptions.ClientException,
                keystone_exceptions.AuthorizationFailure) as exc:
            msg = _('Unable to retrieve authorized projects.')
            raise KeystoneAuthException(msg)

        # Abort if there are no tenants for this user
        if not tenants:
            msg = _('You are not authorized for any projects.')
            raise KeystoneAuthException(msg)

        while tenants:
            tenant = tenants.pop()
            try:
                client = self.get_client().Client(project_id=tenant.id,
                                                  token=unscoped_token.auth_token,
                                                  auth_url=auth_url,
                                                  insecure=insecure)
                #token = client.tokens.authenticate(username=username,
                #                                   token=unscoped_token.auth_token,
                #                                   project_id=tenant.id)
                token = client.auth_ref
                token.id = token.auth_token
                break
            except (keystone_exceptions.ClientException,
                    keystone_exceptions.AuthorizationFailure) as exc:
                token = None
            except Exception as exc:
                token = None

        if token is None:
            msg = _("Unable to authenticate to any available projects.")
            raise KeystoneAuthException(msg)

        # Check expiry for our new scoped token.
        self.check_auth_expiry(token)

        # lcheng: Replace the token with hashed token to reduce token size
        if is_ans1_token(token.auth_token):
            hashed_token = hashlib.md5(token.auth_token).hexdigest()
            token._auth_token = hashed_token
        # If we made it here we succeeded. Create our User!
        # lcheng: V3 returns a tuple of endpoint instead of single URL
        endpoint = client.auth_ref.management_url[0]
        user = create_user_from_token(request,
                                      token,
                                      endpoint)

        if request is not None:
            if is_ans1_token(unscoped_token.auth_token):
                hashed_token = hashlib.md5(unscoped_token.auth_token).hexdigest()
                unscoped_token._auth_token = hashed_token
            request.session['unscoped_token'] = unscoped_token.auth_token
            request.user = user

            # Support client caching to save on auth calls.
            setattr(request, KEYSTONE_CLIENT_ATTR, client)

        LOG.debug('Authentication completed for user "%s".' % username)
        return user

    def get_group_permissions(self, user, obj=None):
        return set()

    def get_all_permissions(self, user, obj=None):
        if user.is_anonymous() or obj is not None:
            return set()
        # TODO: Integrate policy-driven RBAC when supported by Keystone.
        role_perms = set(["openstack.roles.%s" % role['name'].lower()
                          for role in user.roles])
        service_perms = set(["openstack.services.%s" % service['type'].lower()
                          for service in user.service_catalog])
        return role_perms | service_perms

    def has_perm(self, user, perm, obj=None):
        if not user.is_active:
            return False
        return perm in self.get_all_permissions(user, obj)

    def has_module_perms(self, user, app_label):
        if not user.is_active:
            return False
        for perm in self.get_all_permissions(user):
            if perm[:perm.index('.')] == app_label:
                return True
        return False
