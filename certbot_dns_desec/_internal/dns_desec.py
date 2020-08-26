import logging

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

import requests

logger = logging.getLogger(__name__)

# ACCT_URL = "https://desec.io/api/v1/auth/login"
DESEC_API = "https://desec.io/api/v1"


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    description = "Obtain certificates using a DNS TXT record (if you are using desec.io for DNS)."
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(
            add,
            default_propagation_seconds=30,  #'The number of seconds to wait for DNS to propagate before asking the ACME server to verify the DNS record.'
        )
        add("credentials", help="desec credentials INI file.")

    def more_info(self):  # pylint: disable=missing-function-docstring
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the desec API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "desec credentials INI file",
            {"token": f"User access token for desec v1 API. (See {DESEC_API}.)"},
        )

    def _perform(self, domain, validation_name, validation):
        self._get_desec_client().add_txt_record(domain, validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_desec_client().del_txt_record(domain, validation, self.ttl)

    def _get_desec_client(self):
        return _desecClient(self.credentials.conf("api-token"))


class _desecClient(object):

    token: str

    def __init__(self, token):
        self.token = token

    # TXT records
    def add_txt_record(self, domain, challange_token, ttl):
         """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the ISPConfig API
        """
        header = {"Authorization": f"Token {self.token}"}
        data = {
            "type": "TXT",
            "records": [f"{challange_token}"],
            "ttl": ttl,
            "subname": "_acme-challenge.",
        }
        requests.patch(
            f"{DESEC_API}/domains/{domain}/rrsets/", headers=header, json=data
        )

    def del_txt_record(self, domain, challange_token, ttl):
        """
        Delete a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the ISPConfig API
        """
        header = {"Authorization": f"Token {self.token}"}
        data = {
            "type": "TXT",
            "records": [],
            "ttl": ttl,
            "subname": "_acme-challenge.",
        }
        requests.patch(
            f"{DESEC_API}/domains/{domain}/rrsets/", headers=header, json=data
        )

