"""
The `~certbot_dns_desec.dns_desec` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the desec API.


Named Arguments
---------------

========================================  =====================================
``--dns-desec-credentials``               deSEC credentials_ INI file.
                                          (Required)
``--dns-desec-propagation-seconds``       The number of seconds to wait for DNS
                                          to propagate before asking the ACME
                                          server to verify the DNS record.
                                          (Default: 10)
========================================  =====================================


Credentials
-----------

Use of this plugin requires a configuration file containing desec API
credentials, obtained from your
`desec dashboard <https://desec.io/api/v1/auth/login>`_.

desec's newer API Tokens can be restricted to specific domains and
operations, and are therefore now the recommended authentication option.

The Token needed by Certbot requires ``Zone:DNS:Edit`` permissions for only the
zones you need certificates for.


.. code-block:: ini
   :name: certbot_desec_token.ini
   :caption: Example credentials file using restricted API Token (recommended):

   # desec API token used by Certbot
   certbot_dns_desec:dns_desec_token="0123456789abcdef0123456789abcdef01234567"
   certbot_dns_desec:dns_desec_setting_domain="karartest.dedyn.io" 


``--dns-desec-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   desec account. Users who can read this file can use these credentials
   to issue arbitrary API calls on your behalf. Users who can cause Certbot to
   run using these credentials can complete a ``dns-01`` challenge to acquire
   new certificates or revoke existing certificates for associated domains,
   even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``

   certbot certonly \\
     --dns-desec \\
     --dns-desec-credentials ~/.secrets/certbot/desec.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-desec \\
     --dns-desec-credentials ~/.secrets/certbot/desec.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 60 seconds
             for DNS propagation

   certbot certonly \\
     --dns-desec \\
     --dns-desec-credentials ~/.secrets/certbot/desec.ini \\
     --dns-desec-propagation-seconds 60 \\
     -d example.com

"""
