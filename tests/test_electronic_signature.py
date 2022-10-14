# This file is part of Coog. The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
from trytond.tests.test_tryton import ModuleTestCase


class ElectronicSignatureTestCase(ModuleTestCase):
    'Test Electronic Signature module'
    module = 'electronic_signature'


del ModuleTestCase
