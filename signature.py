# This file is part of Coog. The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
import datetime
import xmlrpc.client
import requests

from trytond.config import config as config_parser
from trytond.model import ModelSQL, ModelView, fields
from trytond.pyson import Eval
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


class Signature(ModelSQL, ModelView):
    'Signature'

    __name__ = 'document.signature'

    provider_credential = fields.Many2One('document.signature.credential',
        'Provider Credential', readonly=True)
    attachment = fields.Many2One('ir.attachment', 'Attachment')
    provider_id = fields.Char('Provider ID', readonly=True)
    status = fields.Selection([
        ('issued', 'Issued'),
        ('ready', 'Ready'),
        ('expired', 'Expired'),
        ('canceled', 'Canceled'),
        ('failed', 'Failed'),
        ('completed', 'Completed'),
        ], 'Status', readonly=True)
    logs = fields.Text('Logs', readonly=True)

    @staticmethod
    def default_status():
        return 'issued'

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
            signature.save()
        return response

    @classmethod
    def signer_structure(cls, conf, signer):
        return {
            'last_name': signer.full_name,
            'email': signer.email,
            # Should be mobile but strangely we used phone
            'mobile': signer.mobile or signer.phone,
            'lang': signer.lang.code if signer.lang else '',
            }

    @classmethod
    def signature_position(cls, conf):
        res = {}
        for key in ('page', 'coordinate_x', 'coordinate_y'):
            if key in conf:
                res[key] = conf[key]
        return res

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
    def format_url(cls, url, from_object):
        return url

    @classmethod
    def get_conf(cls, credential=None, config=None, attachment=None,
            from_object=None, extra_data=None):
        res = extra_data or {}
        if not credential or not config:
            company = Pool().get('company.company')(
                Transaction().context.get('company'))
            if not credential and company.signature_credentials:
                credential = company.signature_credentials[0]
            if not config and company.signature_configurations:
                config = company.signature_configurations[0]
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
                    url = url.format(att=attachment)
                elif from_object:
                    url = cls.format_url(from_object)
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
        res['log'] = credential.log_execution if credential else False
        return res

    @classmethod
    def request_transaction(cls, report, attachment=None, from_object=None,
            credential=None, config=None, extra_data=None):
        signature = cls()
        conf = cls.get_conf(credential, config, attachment, from_object,
            extra_data)
        data = cls.get_data_structure(conf, report)
        method = 'init_signature'
        response = cls.call_provider(signature, conf, method, data)
        signature.provider_id = cls.get_provider_id_from_response(conf,
            response)
        signature.attachment = attachment
        signature.save()

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

    def update_transaction_info(self):
        method = 'check_status'
        conf = self.__class__.get_conf(credential=self.provider_credential)
        response = self.__class__.call_provider(self, conf, method,
            self.provider_id)
        status = self.__class__.get_status_from_response(conf['provider'],
            response)
        if self.status != status:
            self.status = status
            self.save()

    @classmethod
    def get_content_from_response(cls, provider, response):
        return getattr(cls, provider + '_get_content_from_response')(
            response)

    def get_documents(self):
        conf = self.__class__.get_conf(credential=self.provider_credential)
        response = self.__class__.call_provider(self, conf,
            'get_signed_document', self.provider_id)
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

    @staticmethod
    def default_company():
        return Transaction().context.get('company') or None

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
