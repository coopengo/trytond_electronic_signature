from werkzeug.exceptions import abort, Response
from trytond.transaction import Transaction
from trytond.wsgi import app
from trytond.protocols.wrappers import with_pool, with_transaction, \
        user_application


@app.route('/<database_name>/electronic_signature/<provider>/callback',
        methods=['GET'])
@with_pool
@with_transaction()
def callback(request, pool, provider):
    Signature = pool.get('document.signature')
    transaction_id = request.args.get('id')
    signer_id = request.args.get('signer')
    status = request.args.get('status')
    Signature.call_back(cls, provider, transaction_id, signer_id, status)
