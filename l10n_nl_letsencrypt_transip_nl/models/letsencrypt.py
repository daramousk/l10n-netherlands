# -*- coding: utf-8 -*-
# Copyright 2018 Therp BV <http://therp.nl>
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).
from odoo import models
import base64
import logging

_logger = logging.getLogger(__name__)

try:
    from transip.service.objects import DnsEntry
    from transip.service.domain import DomainService
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
except ImportError as err:
    _logger.debug(err)


class Letsencrypt(models.AbstractModel):
    _inherit = 'letsencrypt'

    def _respond_challenge_dns_transip(self, challenge, domain):
        """_respond_challenge_dns_transip Creates the TXT record on TransIP.

        :param challenge: An acme.challenges.Challenge object that contains
                          relevant data for this challenge.
        :param domain: A str. The domain that the challenge is for.
        """
        ir_config_parameter = self.env['ir.config_parameter']
        login = ir_config_parameter.get_param('letsencrypt_transip_login')
        key = ir_config_parameter.get_param('letsencrypt_transip_key')
        token = base64.urlsafe_b64encode(challenge.token)
        dns_entry = DnsEntry('_acme-challenge', 60, 'TXT', token)
        key = serialization.load_pem_private_key(
            str(key),
            password=None,
            backend=default_backend())
        key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
        domain = domain.split('*.')[-1]
        DomainService(login, key).set_dns_entries(domain, [dns_entry])
