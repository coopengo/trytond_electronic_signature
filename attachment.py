# This file is part of Coog. The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
from trytond.pool import PoolMeta
from trytond.model import fields
from trytond.pyson import Eval

__all__ = [
    'Attachment',
    ]


class Attachment(metaclass=PoolMeta):
    __name__ = 'ir.attachment'

    signatures = fields.One2Many('document.signature', 'attachment',
        'Signatures')
    signature = fields.Function(
        fields.Many2One('document.signature', 'Signature'),
        'getter_signature')

    @classmethod
    def view_attributes(cls):
        return super(Attachment, cls).view_attributes() + [
            ("/form/notebook/page[@id='e-signature']", 'states', {
                    'invisible': ~Eval('signatures', False)}),
            ]

    def getter_signature(self, name):
        if len(self.signatures) == 1:
            return self.signatures[0].id
        elif len([s for s in self.signatures if s.status == 'completed']) > 0:
            return [s for s in self.signatures
                if s.status == 'completed'][-1].id
        else:
            pendings = [s for s in self.signatures if s.status not in [
                    'failed', 'expired', 'canceled', 'completed']]
            if pendings:
                return pendings[-1].id
            return self.signatures[-1].id if self.signatures else None

    def update_with_signed_document(self, signature):
        self.data = signature.get_documents()
        self.save()
