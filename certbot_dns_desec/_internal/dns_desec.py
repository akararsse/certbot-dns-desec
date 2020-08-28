import logging

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

import requests

logger = logging.getLogger(__name__)

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
            default_propagation_seconds=10,  #'The number of seconds to wait for DNS to propagate before asking the ACME server to verify the DNS record.'
        )
        add("credentials", help="desec credentials INI file.")

    def more_info(self):  # pylint: disable=missing-function-docstring
        return "This plugin configures a DNS TXT record to respond to a dns-01 challenge using the desec API."

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "desec credentials INI file",
            {
                "token": f"User access token for desec v1 API. (See {DESEC_API}.)",
                "setting_domain": f"Setting domain for wildcard and subdomain use cases",
            },
            self._validate_credentials,
        )

    def _validate_credentials(self, credentials):
        token = credentials.conf("token")

    def _perform(self, domain, validation_name, validation):
        print("performming")
        self._get_desec_client().add_txt_record(domain, validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_desec_client().del_txt_record(domain, validation, self.ttl)

    def _get_desec_client(self):
        return _desecClient(
            self.credentials.conf("token"), self.credentials.conf("setting_domain")
        )


class _desecClient(object):

    token: str
    setting_domain: str
    cert_name: str

    def __init__(self, token, setting_domain):
        self.token = token
        self.setting_domain = setting_domain
        
    def wildcardcheck(self):
        if "*" in self.cert_name:
            self.cert_name = self.cert_name.replace("*.", "")
        return self.cert_name

    def subdomaincheck(self, domain):
        self.cert_name = domain.rsplit(self.setting_domain, 1)[0]
        self.cert_name = self.wildcardcheck()
        self.cert_name = self.cert_name.rsplit(".", 1)[0]
        return self.cert_name

    def domainbeautify(self, domain):
        if domain.endswith(self.setting_domain):
            self.cert_name = "_acme-challenge."+self.subdomaincheck(domain)
            if self.cert_name.endswith("."):
                self.cert_name = self.cert_name.rsplit(".", 1)[0]
            domain = domain.replace(domain.rsplit(self.setting_domain, 1)[0], "")
        else:
            self.cert_name="_acme-challenge"
        domain_tuple = (domain, self.cert_name)
        return (domain_tuple)

    # TXT records
    def add_txt_record(self, domain, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the ISPConfig API
        """
        domain, self.cert = self.domainbeautify(domain)
        

        header = {
            "Authorization": f"Token {self.token}",
            "Content-Type": "application/json",
        }
        data = [
            {
                "type": "TXT",
                "records": [f'"{record_content}"'],
                "ttl": record_ttl,
                "subname": f"{self.cert_name}",
            }
        ]
        print(data)
        domain=domain
        print(
            requests.patch(
                f"{DESEC_API}/domains/{domain}/rrsets/", headers=header, json=data
            )
        )

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cache$
        :raises certbot.errors.PluginError: if an error occurs communicating with the ISPConf$
        """
        domain, self.cert = self.domainbeautify(domain)


        header = {
            "Authorization": f"Token {self.token}",
            "Content-Type": "application/json",
        }
        data = [
            {
                "type": "TXT",
                "records": [f'"{record_content}"'],
                "subname": f"{self.cert_name}",
            }
        ]
        print(
            requests.patch(
                f"{DESEC_API}/domains/{domain}/rrsets/", headers=header, json=data
            )
        )

    def _find_txt_record_id(self, domain, record_name):
        header = {
            "Authorization": f"Token {self.token}",
            "Content-Type": "application/json",
        }
        print(
            requests.get(
                f"{DESEC_API}/domains/{domain}/rrsets/{record_name}/TXT/",
                headers=header,
            )
        )
