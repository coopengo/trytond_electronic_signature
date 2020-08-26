# This file is part of Coog. The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.

try:
    from trytond.modules.electronic_signature.tests.test_electronic_signature import suite
except ImportError:
    from .test_electronic_signature import suite

__all__ = ['suite']
