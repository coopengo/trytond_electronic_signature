# This file is part of Coog. The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
from trytond.pool import PoolMeta
from trytond.model import fields

__all__ = [
    'Company',
    ]


class Company(metaclass=PoolMeta):
    __name__ = 'company.company'

    signature_credentials = fields.One2Many('document.signature.credential',
        'company', 'Credentials')
    signature_configurations = fields.One2Many(
        'document.signature.configuration', 'company', 'Configurations')
