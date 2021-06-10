# This file is part of Coog. The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
from werkzeug.exceptions import BadRequest
import datetime
import xmlrpc.client
import requests
from unidecode import unidecode

from trytond import backend
from trytond.i18n import gettext
from trytond.config import config as config_parser
from trytond.model import ModelSQL, ModelView, fields, Workflow
from trytond.pyson import Eval, Not, In
from trytond.pool import Pool
from trytond.transaction import Transaction

__all__ = [
    'SignatureCredential',
    'Signature',
    'SignatureConfiguration',
    ]


class SignatureCredential(ModelSQL, ModelView):
    'Signature Credential'

    __name__ = 'document.signature.credential'

    company = fields.Many2One('company.company', 'Company', required=True,
        ondelete="RESTRICT")
    provider = fields.Selection([('', '')], 'Provider', required=True)
    provider_url = fields.Char('Provider URL', required=True)
    auth_mode = fields.Selection([('basic', 'Basic')], 'Authentication Mode')
    username = fields.Char('User Name',
        states={'required': Eval('auth_mode') == 'basic'},
        depends=['auth_mode'])
    password = fields.Char('Password')
    displayed_password = fields.Function(fields.Char('Password',
            states={'required': Eval('auth_mode') == 'basic'},
            depends=['auth_mode']),
        'get_password', 'set_password')
    prefix_url_success = fields.Char('Prefix URL Success')
    prefix_url_cancel = fields.Char('Prefix URL Cancel')
    prefix_url_fail = fields.Char('Prefix URL Fail')
    log_execution = fields.Boolean('Log Execution',
        help='Set temporary the value to True to debug the call')
    configurations = fields.One2Many('document.signature.configuration',
        'credential', 'Configurations')

    @staticmethod
    def default_auth_mode():
        return 'basic'

    @staticmethod
    def default_company():
        return Transaction().context.get('company') or None

    def get_password(self, name):
        return '*' * 10

    @classmethod
    def set_password(cls, credentials, name, value):
        if value == '*' * 10:
            return
        cls.write(credentials, {'password': value})


class Signature(Workflow, ModelSQL, ModelView):
    'Signature'

    __name__ = 'document.signature'
    _transition_state = 'status'

    provider_credential = fields.Many2One('document.signature.credential',
        'Provider Credential', readonly=True)
    attachment = fields.Many2One('ir.attachment', 'Attachment')
    provider_id = fields.Char('Provider ID', readonly=True)
    provider_url = fields.Char('Provider URL', readonly=True)
    status = fields.Selection([
        ('issued', 'Issued'),
        ('ready', 'Ready'),
        ('expired', 'Expired'),
        ('canceled', 'Canceled'),
        ('failed', 'Failed'),
        ('completed', 'Completed'),
        ('pending_validation', 'Pending Validation'),
        ], 'Status', readonly=True)
    logs = fields.Text('Logs', readonly=True)

    @classmethod
    def __setup__(cls):
        super(Signature, cls).__setup__()
        cls._transitions |= set((
                ('issued', 'ready'),
                ('issued', 'expired'),
                ('issued', 'canceled'),
                ('issued', 'failed'),
                ('issued', 'completed'),
                ('issued', 'pending_validation'),
                ('ready', 'expired'),
                ('ready', 'canceled'),
                ('ready', 'failed'),
                ('ready', 'completed'),
                ('ready', 'pending_validation'),
                ('pending_validation', 'expired'),
                ('pending_validation', 'canceled'),
                ('pending_validation', 'failed'),
                ('pending_validation', 'completed'),
                ))
        cls._buttons.update({
                'update_transaction_info': {
                    'invisible': Not(In(Eval('status'),
                            ['', 'issued', 'ready', 'pending_validation']))},
                'relaunch_transaction': {
                    'invisible': Eval('status') != 'ready'},
                })

    @classmethod
    @Workflow.transition('ready')
    def set_status_ready(cls, signatures):
        pass

    @classmethod
    @Workflow.transition('expired')
    def set_status_expired(cls, signatures):
        pass

    @classmethod
    @Workflow.transition('canceled')
    def set_status_canceled(cls, signatures):
        pass

    @classmethod
    @Workflow.transition('failed')
    def set_status_failed(cls, signatures):
        pass

    @classmethod
    @Workflow.transition('completed')
    def set_status_completed(cls, signatures):
        pass

    @classmethod
    @Workflow.transition('pending_validation')
    def set_status_pending_validation(cls, signatures):
        pass

    @classmethod
    def headers(cls, provider):
        return getattr(cls, provider + '_headers')()

    @classmethod
    def auth(cls, conf):
        auth_mode = conf['auth_mode']
        # For now we only support basic authentication
        assert (auth_mode == 'basic')
        if auth_mode == 'basic':
            username = conf['username']
            assert username
            password = conf['password']
            assert password
            return requests.auth.HTTPBasicAuth(username, password)

    @classmethod
    def call_provider(cls, signature, conf, method, data):
        url = conf['url']
        assert url
        provider_method = cls.get_methods(conf)[method]
        all_data = xmlrpc.client.dumps((data,), provider_method)
        req = requests.post(url, headers=cls.headers(conf['provider']),
            auth=cls.auth(conf), data=all_data)
        if req.status_code > 299:
            raise Exception(req.content)
        response, _ = xmlrpc.client.loads(req.content)
        if conf['log']:
            signature.append_log(conf, method, data, response)
        return response

    @classmethod
    def signer_structure(cls, conf, signer):
        return {
            'last_name': unidecode(signer.full_name),
            'email': signer.email,
            # Should be mobile but strangely we used phone
            'mobile': signer.mobile or signer.phone,
            'lang': signer.lang.code if signer.lang else '',
            }

    @classmethod
    def signature_position(cls, conf, coordinate):
        return coordinate

    @classmethod
    def transcode_structure(cls, conf, method, *args):
        if args:
            struct = getattr(cls, method)(conf, *args)
        else:
            struct = getattr(cls, method)(conf)
        transco = getattr(cls,
            conf['provider'] + '_transcode_%s' % method)(conf)
        new_struct = {}
        for key, value in struct.items():
            if key in transco:
                new_struct[transco[key]] = value
            else:
                new_struct[key] = value
        return new_struct

    @classmethod
    def get_data_structure(cls, conf, report):
        return getattr(cls, conf['provider'] + '_get_data_structure')(report,
            conf)

    @classmethod
    def get_provider_id_from_response(cls, conf, response):
        return getattr(cls,
            conf['provider'] + '_get_provider_id_from_response')(response)

    @classmethod
    def get_provider_url_from_response(cls, conf, response):
        return getattr(cls,
            conf['provider'] + '_get_provider_url_from_response')(response)

    @classmethod
    def format_url(cls, url, from_object):
        return url

    @classmethod
    def get_authentification(cls, credential=None):
        conf = {}
        if not credential:
            Company = Pool().get('company.company')
            company = Company(Transaction().context.get('company'))
            if company.signature_credentials:
                credential = company.signature_credentials[0]
        provider = credential.provider if credential else config_parser.get(
            'electronic_signature', 'provider')
        conf['provider'] = provider
        conf['auth_mode'] = (credential.auth_mode
                if credential else config_parser.get(provider, 'auth_mode'))
        conf['username'] = (credential.username
                if credential else config_parser.get(provider, 'username'))
        conf['password'] = (credential.password
                if credential else config_parser.get(provider, 'password'))
        conf['url'] = (credential.provider_url
                if credential else config_parser.get(provider, 'url'))
        conf['log'] = credential.log_execution if credential else False
        return conf, credential

    @classmethod
    def get_conf(cls, config=None, attachment=None, from_object=None):
        credential = config.credential if config else None
        res, credential = cls.get_authentification(credential)
        provider = res['provider']
        if not config:
            Company = Pool().get('company.company')
            company = Company(Transaction().context.get('company'))
            if (company.signature_credentials
                    and company.signature_credentials[0].configurations):
                credential = company.signature_credentials[0]
                config = credential.signature_configurations[0]
        res['urls'] = {}
        for call in ['success', 'fail', 'cancel']:
            if credential and config and getattr(
                    credential, 'prefix_url_%s' % call):
                url = getattr(credential, 'prefix_url_%s' % call)
                if getattr(config, 'suffix_url_%s' % call):
                    url += getattr(config, 'suffix_url_%s' % call)
            else:
                url = config_parser.get(provider, '%s-url' % call)
            if url is not None:
                if attachment and '{att.' in url:
                    url = url.format(att=attachment)
                elif from_object:
                    url = cls.format_url(url, from_object)
                res['urls'][call] = url
        res['profile'] = config.profile \
            if config and config.profile else 'default'
        res['level'] = config.level if config else 'simple'
        res['send_email_to_sign'] = config.send_email_to_sign \
            if config else True
        res['send_signed_docs_by_email'] = config.send_signed_docs_by_email \
            if config else True
        res['handwritten_signature'] = config.handwritten_signature \
            if config else 'never'
        res['manual'] = config.manual if config else False
        return res, credential

    @classmethod
    def request_transaction(cls, report, attachment, from_object=None,
            config=None, ignore_manual=True):
        conf, credential = cls.get_conf(config, attachment, from_object)
        if ignore_manual and conf['manual']:
            return
        signature = cls()
        data = cls.get_data_structure(conf, report)
        method = 'init_signature'
        response = cls.call_provider(signature, conf, method, data)
        signature.provider_id = cls.get_provider_id_from_response(conf,
            response)
        signature.provider_url = cls.get_provider_url_from_response(conf,
            response)
        signature.status = 'issued'
        signature.provider_credential = credential
        return signature

    def notify_signature_completed(self):
        self.attachment.update_with_signed_document(self)

    def notify_signature_failed(self):
        # TODO Trigger an event
        pass

    @classmethod
    def call_back(cls, provider, provider_id, signer_id, provider_status):
        domain = [
            [('provider_id', '=', provider_id)],
            ['OR',
                [('provider_credential', '=', None)],
                [('provider_credential.provider', '=', provider)]]
            ]
        signatures = cls.search(domain)
        if len(signatures) != 1:
            raise BadRequest(gettext(
                    'electronic_signature.msg_unknown_signature',
                    provider_id=provider_id, provider=provider))
        signature = signatures[0]
        new_status = getattr(cls, provider + '_transcode_status')()[
            provider_status]
        signature.update_status(new_status)

    def update_status(self, new_status):
        if new_status == self.status:
            return
        transition = (self.status, new_status)
        if transition not in self.__class__._transitions:
            raise BadRequest(gettext(
                    'electronic_signature.msg_unauthorized_transition',
                    provider_id=self.provider_id,
                    provider=self.provider_credential.provider
                    if self.provider_credential else '',
                    status=new_status))
        if self.status != new_status:
            # the transition writes the status on the signature
            getattr(self.__class__, 'set_status_%s' % new_status)([self])

            # now that the status is updated in database, we can notify
            if new_status in ('expired', 'canceled'):
                self.notify_signature_failed()
            elif new_status == 'completed':
                self.notify_signature_completed()

    def append_log(self, conf, method, data, response):
        if not hasattr(self, 'logs') or not self.logs:
            self.logs = ''
        self.logs += '%s @ %s\n%s\n%s\n\n' % (
            self.__class__.get_methods(conf)[method],
            datetime.datetime.utcnow(), data, response)

    @classmethod
    def get_methods(cls, conf):
        return getattr(cls, conf['provider'] + '_get_methods')()

    @classmethod
    def get_status_from_response(cls, provider, response):
        return getattr(cls, provider + '_get_status_from_response')(
            response)

    @classmethod
    @ModelView.button
    def update_transaction_info(cls, signatures):
        method = 'check_status'
        for signature in signatures:
            conf, _ = cls.get_authentification(signature.provider_credential)
            response = cls.call_provider(signature, conf, method,
                signature.provider_id)
            signature.update_status(cls.get_status_from_response(
                    conf['provider'], response))

    @classmethod
    @ModelView.button
    def relaunch_transaction(cls, signatures):
        for signature in signatures:
            conf, _ = cls.get_authentification(signature.provider_credential)
            cls.call_provider(signature, conf, 'relaunch',
                signature.provider_id)

    @classmethod
    def get_content_from_response(cls, provider, response):
        return getattr(cls, provider + '_get_content_from_response')(
            response)

    def get_documents(self):
        conf, _ = self.__class__.get_authentification(self.provider_credential)
        response = self.__class__.call_provider(self, conf,
            'get_signed_document', self.provider_id)
        return self.__class__.get_content_from_response(conf['provider'],
            response)


class SignatureConfiguration(ModelSQL, ModelView):
    'Signature Configuration'

    __name__ = 'document.signature.configuration'

    credential = fields.Many2One('document.signature.credential', 'Credential',
        required=True, ondelete='CASCADE')
    profile = fields.Char('Profile')
    level = fields.Selection([
            ('simple', 'Simple'),
            ('certified', 'Certified'),
            ('advanced', 'Advanced')], 'Level', sort=False)
    level_string = level.translated('level')
    send_email_to_sign = fields.Boolean('Send an e-mail to sign',
        help='Send an email to first signer to proceed with the electronic '
        'signature')
    send_signed_docs_by_email = fields.Boolean(
        'Send signed documents by e-mail',
        help='Send an e-mail to each signer with the signed documents at the '
        'end of the process')
    handwritten_signature = fields.Selection([
        ('never', 'Never'),
        ('always', 'Always'),
        ('touch_interface', 'On Touch Interface')], 'Handwritten Signature',
        sort=False)
    suffix_url_success = fields.Char('Suffix URL Success')
    suffix_url_cancel = fields.Char('Suffix URL Cancel')
    suffix_url_fail = fields.Char('Suffix URL Fail')
    manual = fields.Boolean('Manual',
        help='If set the electronic process will not be triggered '
        'automatically when the attachment is created')

    @classmethod
    def __register__(cls, module_name):
        configuration_h = backend.TableHandler(cls)
        Credential = Pool().get('document.signature.configuration')
        super().__register__(module_name)

        # Migration from coog 2.6 Link configuration to credential
        if configuration_h.column_exist('company'):
            table = cls.__table__()
            credential = Credential.__table__()
            cursor = Transaction().connection.cursor()
            cursor.execute(*credential.select(credential.id))
            result = cursor.fetchone()

            if result is not None:
                credential_id = result[0]
                cursor.execute(*table.update(
                        columns=[table.credential],
                        values=[credential_id]))

            configuration_h.drop_column('company')

    @staticmethod
    def default_level():
        return 'simple'

    @staticmethod
    def default_handwritten_signature():
        return 'never'

    @staticmethod
    def default_send_email_to_sign():
        return True

    @staticmethod
    def default_send_signed_docs_by_email():
        return True

    def get_rec_name(self, name=None):
        return '%s [%s]' % (self.profile, self.level_string)
