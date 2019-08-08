# This file is part of Coog. The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
import datetime
import xmlrpc.client
import requests

from trytond.config import config as config_parser
from trytond.model import ModelSQL, ModelView, fields
from trytond.pyson import Eval
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
        to_write = [[[c], {'password': value}] for c in credentials]
        cls.write(*to_write)


class Signature(ModelSQL, ModelView):
    'Signature'

    __name__ = 'document.signature'

    provider_credential = fields.Many2One('document.signature.credential',
        'Provider Credential', readonly=True)
    attachment = fields.Many2One('ir.attachment', 'Attachment')
    provider_id = fields.Char('Provider ID', readonly=True)
    status = fields.Selection([
        ('', ''),
        ('issued', 'Issued'),
        ('ready', 'Ready'),
        ('expired', 'Expired'),
        ('canceled', 'Canceled'),
        ('failed', 'Failed'),
        ('completed', 'Completed'),
        ], 'Status', readonly=True)
    logs = fields.Text('Logs', readonly=True)

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
    def call_provider(cls, conf, method, data):
        url = conf['url']
        assert url
        verify = True
        if config_parser.get(conf['provider'], 'no_verify') == '1':
            verify = False
        provider_method = cls.get_methods(conf)[method]
        data = xmlrpc.client.dumps((data,), provider_method)
        req = requests.post(url, headers=cls.headers(conf['provider']),
            auth=cls.auth(conf), data=data,
            verify=verify)
        if req.status_code > 299:
            raise Exception(req.content)
        response, _ = xmlrpc.client.loads(req.content)
        return response

    @classmethod
    def get_signer_structure(cls, signer):
        return {
            'first_name': '',
            'last_name': signer.full_name,
            'birth_date': '',
            'email': signer.email,
            'phone': signer.phone,
            }

    @classmethod
    def get_transcoded_signer_structure(cls, conf, signer):
        struct = cls.get_signer_structure(signer)
        transco = cls.getattr(cls,
            conf['provider'] + '_transcode_signer_structure')()
        new_struct = {}
        for key, value in struct.iteritems():
            struct[transco[key]] = value
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
    def format_url(cls, url, from_object):
        return url

    @classmethod
    def get_conf(cls, credential=None, config=None, attachment=None,
            from_object=None):
        res = {}
        provider = credential.provider if credential else config_parser.get(
            'electronic_signature', 'provider')
        res['provider'] = provider
        res['auth_mode'] = (credential.auth_mode
                if credential else config_parser.get(provider, 'auth_mode'))
        res['username'] = (credential.username
                if credential else config_parser.get(provider, 'username'))
        res['password'] = (credential.password
                if credential else config_parser.get(provider, 'password'))
        res['url'] = (credential.provider_url
                if credential else config_parser.get(provider, 'url'))
        res['urls'] = {}
        for call in ['success', 'fail', 'cancel']:
            if credential and config:
                url = getattr(credential, 'prefix_url_%s' % call) + getattr(
                    config, 'suffix_url_%s' % call)
            else:
                url = config_parser.get(provider, '%s-url' % call)
            if url is not None:
                if attachment and '{att.' in url:
                    url.format(att=attachment)
                elif from_object:
                    url = cls.format_url(from_object)
                res['urls'][call] = url
        return res

    @classmethod
    def request_transaction(cls, report, attachment=None, from_object=None,
            credential=None, config=None):
        signature = cls()
        conf = cls.get_conf(credential, config, attachment, from_object)
        data = cls.get_data_structure(conf, report)
        method = 'init_signature'
        response = cls.call_provider(conf, method, data)
        signature.status = 'issued'
        signature.append_log(method, response)
        signature.provider_id = cls.get_provider_id_from_response(conf,
            response)
        signature.attachment = attachment
        signature.save()

    def append_log(self, method, response):
        self.logs = getattr(self, 'logs', '')
        self.logs += '%s @ %s\n%s\n\n' % (
            self.__class__.get_methods()[method],
            datetime.datetime.utcnow(), response)

    @classmethod
    def get_methods(cls, conf):
        return getattr(cls, conf['provider'] + '_get_methods')()

    @classmethod
    def get_status_from_response(cls, provider, response):
        return getattr(cls, provider + '_get_status_from_response')(
            response)

    def update_transaction_info(self):
        method = 'check_status'
        conf = self.__class__.get_conf(credential=self.provider_credential)
        response = self.__class__.call_provider(conf, method, self.provider_id)
        status = self.__class__.get_status_from_response(conf['provider'],
            response)
        if self.status != status:
            self.append_log(method, response)
            self.status = status
            self.save()

    @classmethod
    def get_content_from_response(cls, provider, response):
        return getattr(cls, provider + '_get_content_from_response')(
            response)

    def get_documents(self):
        conf = self.__class__.get_conf(credential=self.provider_credential)
        response = self.__class__.call_provider(conf, 'get_signed_document',
            self.provider_id)
        return self.__class__.get_content_from_response(conf['provider'],
            response)


class SignatureConfiguration(ModelSQL, ModelView):
    'Signature Configuration'

    __name__ = 'document.signature.configuration'

    company = fields.Many2One('company.company', 'Company', required=True,
        ondelete="RESTRICT")
    profile = fields.Char('Profile')
    level = fields.Selection([
            ('simple', 'Simple'),
            ('certified', 'Certified'),
            ('advanced', 'Advanced')], 'Level', sort=False)
    send_email_to_sign = fields.Boolean('Send an e-mail to sign',
        help='Send an email to first signer to proceed with the electronic '
        'signature')
    send_signed_docs_by_email = fields.Boolean(
        'Send signed documents by e-mail',
        help='Send an e-mail to each signer with the signed documents at the '
        'end of the process')
    description = fields.Char('Description',
        help='Textual description of the meta data for the request')
    lang = fields.Many2One('ir.lang', 'Lang',
        help='Page language for the signers')
    handwritten_signature = fields.Selection([
        ('never', 'Never'),
        ('always', 'Always'),
        ('touch_interface', 'On Touch Interface')], 'Hanwritten Signature',
        sort=False)
    suffix_url_success = fields.Char('Suffix URL Success')
    suffix_url_cancel = fields.Char('Suffix URL Cancel')
    suffix_url_fail = fields.Char('Suffix URL Fail')

    @staticmethod
    def default_company():
        return Transaction().context.get('company') or None

    @staticmethod
    def default_level():
        return 'simple'

    @staticmethod
    def default_handwritten_signature():
        return 'never'
