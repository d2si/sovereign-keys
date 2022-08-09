import json
import os
import time
from threading import Thread
from utils import logger, b64_to_bin, bin_to_b64, compute_aad, HTTPError

from skpkcs11 import BadPINException

#########################################
# BEGIN: Sovereign Keys Token Interface #
#########################################
# Here we chose the appropriate sk_token_interface that allow the API to
# perform cryptographic operations

# If the HSM is a Bull (Atos) Proteccio NetHSM
if os.environ['HSM_TYPE'] == 'proteccio':
    import sktokeninterface.proteccio as sk_token_interface
elif os.environ['HSM_TYPE'] == 'cloudhsm':
    import sktokeninterface.cloudhsm as sk_token_interface
else:
    raise Exception(f"Unknown HSM type: {os.environ['HSM_TYPE']}")

#########################################
#  END: Sovereign Keys Token Interface  #
#########################################

#########################
# Sovereign Keys Logger #
#########################
from sklogger import SKLogEntry
SKLogEntry.set_sign_function(sk_token_interface.sign)

###############
# ETCD client #
###############
import etcd
etcd_client = etcd.Client(host='127.0.0.1', port=2379, read_timeout=1)

####################
# AWS Interactions #
####################
from utils import DynamoDBInfoTableCache
info_table_cache = DynamoDBInfoTableCache(os.environ['VPC_INFOS_TABLE'])
SKLogEntry.set_info_table_cache(info_table_cache)

import boto3
from hashlib import md5
AWS_DEFAULT_REGION = os.environ['AWS_DEFAULT_REGION']
EKT_BUCKET = os.environ['EKT_BUCKET']
s3 = boto3.client('s3', region_name=AWS_DEFAULT_REGION)

def s3_key_from_vpc(vpc_id):
    item = info_table_cache.get_info_item(vpc_id)
    if 'EktName' in item:
        return f"{item['EktName']}.ekt"
    return f"{vpc_id}.ekt"

def get_ekt_for_vpc(vpc_id):
    key = s3_key_from_vpc(vpc_id)
    logger.debug(f'Retrieving EKT from s3://{EKT_BUCKET}/{key}')
    try:
        return s3.get_object(
            Bucket=EKT_BUCKET,
            Key=key
        )['Body'].read()
    except s3.exceptions.NoSuchKey:
        logger.info(f'No EKT found in S3 for VPC {vpc_id}')
        return None

def store_ekt_for_vpc(ekt, vpc_id):
    key = s3_key_from_vpc(vpc_id)
    logger.debug(f'Storing EKT to s3://{EKT_BUCKET}/{key}')
    s3.put_object(
        Bucket=EKT_BUCKET,
        Key=key,
        Body=ekt,
        ContentMD5=bin_to_b64(md5(ekt).digest())
    )

def get_or_create_ekt(vpc_id):
    logger.info(f'Trying to get EKT for {vpc_id} in S3...')
    ekt = get_ekt_for_vpc(vpc_id)
    if ekt is None:
        logger.info(f'EKT does not exist for {vpc_id}. Creating it...')
        aad = compute_aad({'vpc_id':vpc_id})
        ekt = sk_token_interface.create_new_ekt(aad)
        logger.info(f'Storing new EKT in S3...')
        store_ekt_for_vpc(ekt, vpc_id)
    return ekt

###############
# Path parser #
###############
from urllib.parse import unquote_plus
import re
path_to_reg = re.compile(r'/\{(.+?)\}')
match_dict = {
    'GET':{},
    'POST':{},
    'PUT':{}
}

def path_to_regex(path):
    # The substitution will extract the pattern "/{some_name}" in a path that signal a path parameter
    # And replace it by "/(?P<some_name>.+?)" which is the Regexp that will extract the value and set it in a match group named "some_name"
    return re.compile('^' + path_to_reg.sub(r'/(?P<\g<1>>.+?)', path) + '$')

class post:
    def __init__(self, path):
        self.path = path
    def __call__(self, func):
        match_dict['POST'][path_to_regex(self.path)] = func

class get:
    def __init__(self, path):
        self.path = path
    def __call__(self, func):
        match_dict['GET'][path_to_regex(self.path)] = func

class put:
    def __init__(self, path):
        self.path = path
    def __call__(self, func):
        match_dict['PUT'][path_to_regex(self.path)] = func

def parse_path(verb, path):
    for r, func in match_dict[verb].items():
        m = r.match(path)
        if m is not None:
            # Return a tuble of (path, pathParameter)
            # With "path" being
            return func, m.groupdict()
    raise HTTPError(400, 'Unimplemented')

################
# Health check #
################
import requests
def spot_instance_will_be_shutdown():
    r = requests.get('http://169.254.169.254/latest/meta-data/spot/instance-action')
    if r.status_code == 200:
        logger.warning('This spot instance will be shutdown...')
        return True
    return False

from datetime import datetime, timedelta
HEALTHY_STATUS={
    'last_real_check': datetime.fromtimestamp(0),
    'healthy': False
}

def test_health():
    return sk_token_interface.is_token_ready()

def get_health_status():
    global HEALTHY_STATUS
    if datetime.now() > HEALTHY_STATUS['last_real_check'] + timedelta(seconds=5):
        HEALTHY_STATUS['last_real_check'] = datetime.now()
        HEALTHY_STATUS['healthy'] = test_health()
        HEALTHY_STATUS['spot_shutdown'] = spot_instance_will_be_shutdown()
        logger.debug(f'Updated HEALTHY_STATUS={HEALTHY_STATUS}')
    return HEALTHY_STATUS

def is_healthy():
    status = get_health_status()
    return status['healthy'] and not status['spot_shutdown']

#######################
# Real core functions #
#######################
@post('/v1/encryption/{InstanceId}/generate-secret')
def generate_secret(params, sle):
    if not all(arg in params for arg in ('InstanceId', 'vpc_id', 'volume_uuid', 'rsa_wrapping_key')):
        raise HTTPError(400, 'Bad parameters')
    instance_id = params['InstanceId']
    vpc_id = params['vpc_id']
    volume_uuid = params['volume_uuid']
    rsa_wrapping_key = params['rsa_wrapping_key']
    sle.set_call('generate-secret', {'instance_id':instance_id, 'volume_uuid':volume_uuid, 'rsa_wrapping_key':rsa_wrapping_key})
    sle.set_caller('INSTANCE', instance_id, params['client_ip'])
    logger.info(f'Retrieve EKT for VPC ID: {vpc_id}')
    ekt = get_or_create_ekt(vpc_id)
    ekt_aad = compute_aad({'vpc_id':vpc_id})
    secret_aad = compute_aad({'instance_id':instance_id, 'volume_uuid':volume_uuid})
    logger.debug(f'EKT for VPC {vpc_id} is: {bin_to_b64(ekt)}')
    logger.info(f'Generating new secret for instance {instance_id}...')
    logger.debug(f"Generating a new secret encrypted with auth_data={{'instance_id':{instance_id}, 'volume_uuid':{volume_uuid}}} and wrapping the result with {rsa_wrapping_key}")
    (   aes_wrapped_secret,
        aes_wrapped_secret_sig,
        rsa_wrapped_secret,
        rsa_wrapped_secret_sig
    ) = sk_token_interface.generate_new_secret(
        secret_aad=secret_aad,
        ekt=ekt,
        ekt_aad=ekt_aad,
        rsa_pub_key=b64_to_bin(rsa_wrapping_key)
    )
    return {
        'encrypted_secret': bin_to_b64(aes_wrapped_secret),
        'encrypted_secret_signature': bin_to_b64(aes_wrapped_secret_sig),
        'wrapped_secret': bin_to_b64(rsa_wrapped_secret),
        'wrapped_secret_signature': bin_to_b64(rsa_wrapped_secret_sig)
    }

@post('/v1/encryption/{InstanceId}/decrypt-secret')
def decrypt_secret(params, sle):
    if not all(arg in params for arg in ('InstanceId', 'vpc_id', 'encrypted_secret', 'volume_uuid', 'rsa_wrapping_key')):
        raise HTTPError(400, 'Bad parameters')
    instance_id = params['InstanceId']
    vpc_id = params['vpc_id']
    volume_uuid = params['volume_uuid']
    encrypted_secret = params['encrypted_secret']
    rsa_wrapping_key = params['rsa_wrapping_key']
    sle.set_call('decrypt-secret', {'instance_id':instance_id, 'volume_uuid':volume_uuid, 'rsa_wrapping_key':rsa_wrapping_key})
    sle.set_caller('INSTANCE', instance_id, params['client_ip'])
    logger.info(f'Retrieve EKT for VPC ID: {vpc_id}')
    ekt = get_ekt_for_vpc(vpc_id)
    ekt_aad = compute_aad({'vpc_id':vpc_id})
    if ekt is None:
        raise HTTPError(400, 'There is no encryption key for this VPC')
    secret_aad = compute_aad({'instance_id':instance_id, 'volume_uuid':volume_uuid})
    logger.debug(f'EKT for VPC {vpc_id} is: {bin_to_b64(ekt)}')
    logger.info(f'Deciphering secret for instance {instance_id}')
    logger.debug(f"Deciphering encrypted_secret={encrypted_secret} with auth_data={{'instance_id':{instance_id}, 'volume_uuid':{volume_uuid}}} and wrapping the result with {rsa_wrapping_key}")
    (   rsa_wrapped_secret,
        rsa_wrapped_secret_sig
    ) = sk_token_interface.decrypt_secret(
        aes_wrapped_secret=b64_to_bin(encrypted_secret),
        secret_aad=secret_aad,
        ekt=ekt,
        ekt_aad=ekt_aad,
        rsa_pub_key=b64_to_bin(rsa_wrapping_key)
    )
    return {
        'wrapped_secret': bin_to_b64(rsa_wrapped_secret),
        'wrapped_secret_signature': bin_to_b64(rsa_wrapped_secret_sig)
    }

@post('/v1/encryption/{InstanceId}/convert-secret')
def convert_secret(params, sle):
    if not all(arg in params for arg in ('InstanceId', 'vpc_id', 'encrypted_secret', 'volume_uuid', 'source_instance_id')):
        raise HTTPError(400, 'Bad parameters')
    instance_id = params['InstanceId']
    vpc_id = params['vpc_id']
    volume_uuid = params['volume_uuid']
    encrypted_secret = params['encrypted_secret']
    source_instance_id = params['source_instance_id']
    sle.set_call('convert-secret', {'instance_id':instance_id, 'volume_uuid':volume_uuid, 'source_instance_id': source_instance_id})
    sle.set_caller('INSTANCE', instance_id, params['client_ip'])
    logger.info(f'Retrieve EKT for VPC ID: {vpc_id}')
    ekt = get_ekt_for_vpc(vpc_id)
    ekt_aad = compute_aad({'vpc_id':vpc_id})
    if ekt is None:
        raise HTTPError(400, 'There is no encryption key for this VPC')
    old_secret_aad = compute_aad({'instance_id':source_instance_id, 'volume_uuid':volume_uuid})
    new_secret_aad = compute_aad({'instance_id':instance_id, 'volume_uuid':volume_uuid})
    logger.debug(f'EKT for VPC {vpc_id} is: {bin_to_b64(ekt)}')
    logger.info(f'Converting secret from instance {source_instance_id} to instance {instance_id}')
    logger.debug(f'Converting encrypted_secret={encrypted_secret} with auth_data={{{source_instance_id},{volume_uuid}}} to auth_data={{{instance_id},{volume_uuid}}}')
    (   new_aes_wrapped_secret,
        new_aes_wrapped_secret_sig
    ) = sk_token_interface.reencrypt_secret(
        aes_wrapped_secret=b64_to_bin(encrypted_secret),
        old_secret_aad=old_secret_aad,
        new_secret_aad=new_secret_aad,
        ekt=ekt,
        ekt_aad=ekt_aad
    )
    return {
        'encrypted_secret': bin_to_b64(new_aes_wrapped_secret),
        'encrypted_secret_signature': bin_to_b64(new_aes_wrapped_secret_sig)
    }


@get('/v1/public-signing-key')
def get_pub_sign_key(params):
    pub_key_bin = sk_token_interface.export_public_signing_key()
    logger.debug(f'EC public key: {bin_to_b64(pub_key_bin)}')
    return {
        'public_key': bin_to_b64(pub_key_bin)
    }

@get('/healthcheck')
def healthcheck(params):
    if not is_healthy():
        logger.warning(f'Healthcheck failed')
        raise HTTPError(500, 'Unhealthy')
    return None

###############
# HTTP SERVER #
###############
def http_exception_handler(method):
    def _wrapper(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except HTTPError as e:
            logger.error(f'Error while serving {self.command} {self.path} from {self.client_address}')
            logger.error(f'{e.code} - {e.message}')
            self.send_error(e.code, message=e.message)
    return _wrapper

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class SovereignAPI(BaseHTTPRequestHandler):
    def response_success(self, obj):
        if obj is None:
            self.response_success_empty()
            return
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())
        logger.debug(f'Request successfully served')

    def response_success_empty(self):
        self.send_response(204)
        self.end_headers()
        logger.debug(f'Request successfully served')

    def extract_body(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        logger.debug(f'Body: {post_data}')
        return json.loads(post_data)

    @http_exception_handler
    def do_GET(self):
        logger.debug(f'Serving request: GET {self.path} for client {self.client_address}')
        func, path_parameters = parse_path('GET', self.path)
        params = {'client_ip':self.address_string()}
        params.update(path_parameters)
        try:
            res = func(params)
        except HTTPError:
            raise
        except:
            logger.exception('Error!!')
            raise HTTPError(500, 'Internal Server Error')
        self.response_success(res)

    @http_exception_handler
    def do_POST(self):
        logger.debug(f'Serving request: POST {self.path} for client {self.client_address}')
        if not is_healthy():
            raise HTTPError(500, 'Unhealthy')
        logger.debug(f'Headers: {self.headers}')
        func, path_parameters = parse_path('POST', self.path)
        # Extract origin VPC
        params = {'vpc_id': self.headers['x-amzn-vpc-id'], 'client_ip': self.headers['X-Forwarded-For']}
        params.update(self.extract_body())
        params.update(path_parameters)
        try:
            with SKLogEntry(params['vpc_id']) as sle:
                res = func(params, sle)
        except HTTPError:
            raise
        except:
            logger.exception('Error!!')
            raise HTTPError(500, 'Internal Server Error')
        self.response_success(res)


    # This is only for PUT /hsm-pin and only accessible from lo
    @http_exception_handler
    def do_PUT(self):
        logger.debug(f'Serving request: PUT {self.path} for client {self.client_address}')
        if self.address_string() != '127.0.0.1':
            raise HTTPError(403, 'PUT /hsm-pin and PUT /client-key can only be done localy')
        logger.debug(f'Headers: {self.headers}')
        try:
            etcd_client.members
        except:
            logger.exception('ETCD Layer is dead')
            raise HTTPError(500, 'ETCD not reachable. Try again later')
        if self.path == '/hsm-pin':
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if 'pin' not in body:
                raise HTTPError(400, 'Missing "pin" in body')
            try:
                pin = body['pin'].encode()
                sk_token_interface.set_pin(pin)
                etcd_client.write('/secrets/hsm_pin_b64', bin_to_b64(pin), prevExist=False)
                logger.info('PIN was set and added to ETCD')
            except BadPINException:
                logger.exception('PIN was not accepted')
                raise HTTPError(400, 'PIN was not accepted')
            except etcd.EtcdAlreadyExist:
                logger.exception('The PIN is already present and cannot be replaced')
                raise HTTPError(400, 'PIN already present')
            except:
                logger.exception('Failed to set PIN')
                raise HTTPError(500, 'Failed to set PIN')
        elif self.path == '/client-key':
            # The Body is the key
            key_content = self.rfile.read(int(self.headers['Content-Length']))
            try:
                etcd_client.write('/secrets/client_key', key_content, prevExist=False)
                logger.info('Added the CLIENT KEY to ETCD as it was absent')
            except etcd.EtcdAlreadyExist:
                logger.exception('The client KEY is already present and cannot be replaced')
                raise HTTPError(400, 'CLIENT KEY already present')
            except:
                logger.exception('Unknown error while trying to set the CLIENT KEY')
                raise HTTPError(500, 'Failed to set the CLIENT KEY')
        else:
            raise HTTPError(400, 'Incorrect method')
        self.response_success_empty()

    def log_message(self, format, *args):
        return

#####################
#   KEY/PIN GETTER  #
#####################
def get_token_pin():
    # Endlessly try to connect to etcd
    while True:
        try:
            etcd_client.members
            break
        except:
            logger.error('ETCD layer cannot be reached. Retrying...')
            time.sleep(5)
    logger.info('ETCD layer is live')

    # Then endlessly try to get the KEYFILE from ETCD
    keyfile_set = False
    while not keyfile_set:
        try:
            key_content = etcd_client.read('/secrets/client_key').value
            with open(os.environ['KEY_FILE'], 'w') as kf:
                kf.write(key_content)
            keyfile_set = True
            break
        except etcd.EtcdKeyNotFound:
            logger.error('Client private key is not present in ETCD')
        except:
            logger.exception('Unknown error while trying to aquire the private key')
        time.sleep(5)
    logger.info('Found the private key')

    # Then endlessly try to get the PIN from ETCD
    while not sk_token_interface.is_token_ready():
        try:
            sk_token_interface.set_pin(b64_to_bin(etcd_client.read('/secrets/hsm_pin_b64').value))
            break
        except etcd.EtcdKeyNotFound:
            logger.error('HSM PIN is not present in ETCD')
        except BadPINException:
            logger.error('PIN found in ETCD is incorrect')
            logger.info('Deleting PIN in ETCD')
            etcd_client.delete('/secrets/hsm_pin_b64')
        except:
            logger.exception('Unknown error while trying to aquire the PIN')
        time.sleep(5)
    logger.info('Found the correct PIN')

    logger.info('thread stopped')
Thread(target=get_token_pin, name='get_token_pin').start()

########
# MAIN #
########
hostName = '0.0.0.0'
serverPort = 8080
webServer = ThreadingHTTPServer((hostName, serverPort), SovereignAPI)
logger.info(f'Server started http://{hostName}:{serverPort}')
try:
    webServer.serve_forever()
except KeyboardInterrupt:
    logger.info(f'Received interruption')

webServer.server_close()
logger.info(f'Server closed')
