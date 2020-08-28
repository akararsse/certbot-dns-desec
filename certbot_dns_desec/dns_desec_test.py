import unittest

try:
    import mock
except ImportError:
    from unittest import mock

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

API_TOKEN = 'an-api-token'

API_KEY = 'an-api-key'

class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_desec._internal.dns_desec import Authenticator

        super (AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write(
            {
                "desec_email": EMAIL, 
                "desec_api_key": API_KEY
            },
            path,
        )

        self.config = mock.MagicMock(
            desec_credentials=path, desec_propagation_seconds=0
        )#no waiting during testing

        self.auth = Authenticator(self.config, "desec")

        self.mock_client = mock.MagicMock()
        # _get_desec_client | pylint: disable=protected-access
        self.auth._get_desec_client = mock.MagicMock(return_value=self.mock_client)
    
    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)
