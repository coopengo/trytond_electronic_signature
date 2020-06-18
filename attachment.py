# This file is part of Coog. The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
from unidecode import unidecode

from trytond.pool import PoolMeta, Pool
from trytond.model import fields, ModelView
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
    can_create_new_signature = fields.Function(
        fields.Boolean('Can Create New Signature'),
        'on_change_with_can_create_new_signature')
    can_see_signatures = fields.Function(
        fields.Boolean('Can See Signatures'),
        'on_change_with_can_see_signatures')

    @classmethod
    def __setup__(cls):
        super(Attachment, cls).__setup__()
        cls._buttons.update({
                'init_new_signature_process': {
                    'invisible': ~Eval('can_create_new_signature')}
                })

    @classmethod
    def view_attributes(cls):
        return super(Attachment, cls).view_attributes() + [
            ("/form/notebook/page[@id='e-signature']", 'states', {
                    'invisible': ~Eval('can_see_signatures', False)}),
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

    @classmethod
    @ModelView.button
    def init_new_signature_process(cls, attachments):
        for attachment in attachments:
            attachment.create_new_signature(ignore_manual=False)
        cls.save(attachments)

    def create_new_signature(self, report=None, from_object=None,
            config=None, ignore_manual=True):
        Signature = Pool().get('document.signature')
        signatures = list(getattr(self, 'signatures', []))
        report = self.get_struct_for_signature(report)
        if report:
            signature = Signature.request_transaction(report, self,
                from_object or self.origin,
                config or self.get_signature_configuration(), ignore_manual)
            if signature:
                signatures.append(signature)
                self.signatures = signatures

    def get_party(self, report=None):
        if report and 'party' in report:
            return report['party']
        elif self.resource.__name__ == 'party.party':
            return self.resource

    def get_struct_for_signature(self, report=None):
        if not report:
            report = {
                'report_name': self.name,
                'data': self.data,
                }
        report['report_name'] = unidecode(report['report_name'])
        party = self.get_party(report)
        if party and party.email:
            report['signers'] = [party]
            return report

    def get_signature_configuration(self):
        return None

    @fields.depends('signatures')
    def on_change_with_can_create_new_signature(self, name=None):
        if not self.signatures:
            return True
        elif self.signature.status == 'completed':
            # The process is completed
            return False
        elif any([s.status in ['issued', 'ready',
                    'pending_validation'] for s in self.signatures]):
            # Pending process
            return False
        elif self.signature.status in ['expired', 'canceled', 'failed']:
            # Process failed, we'll start a new one
            return True

    def on_change_with_can_see_signatures(self, name=None):
        return True
