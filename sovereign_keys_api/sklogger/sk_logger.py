from threading import Thread
import os
from hashlib import md5
import json
from datetime import datetime

#################
# AWS resources #
#################
import boto3
AWS_DEFAULT_REGION = os.environ['AWS_DEFAULT_REGION']
vpc_infos_table_name = os.environ['VPC_INFOS_TABLE']
audit_bucket_name = os.environ['AUDIT_BUCKET']
sts_client = boto3.client('sts', region_name=AWS_DEFAULT_REGION)

###############
# ETCD client #
###############
import etcd
etcd_client = etcd.Client(host='127.0.0.1', port=2379, read_timeout=1)

#########
# Utils #
#########
from utils import logger, bin_to_b64, HTTPError

#######################
# Destination Senders #
#######################
class S3Sender:
    def __init__(self, bucket):
        self._bucket = bucket

    def send(self, sle):
        key = '%s/%09d.json' % (sle.vpc_id, sle.vpc_op_seq_num)
        self._bucket.put_object(
            Key=key,
            Body=sle.data_to_send,
            ContentMD5=sle.data_md5_b64
        )

"""
{
    "event_version": 1,
    "vpc_op_seq_num": 34,
    "vpc_id": "vpc-1234567890abcdef",
    "op_start": "2021-06-05T13:44:39.390805",
    "op_end": "2021-06-05T13:44:44.394534",
    "caller":{
        "type": "INSTANCE",
        "id": "i-1234567890abcdef",
        "ip": "10.42.12.13",
        "aws_account_id": "123456789012"
    },
    "call": "decrypt-secret",
    "call_parameters":{
        "instance_id": "i-1234567890abcdef",
        "volume_uuid": "39331fb1-f6b0-4a1f-b873-3490d3f1e491",
        "rsa_wrapping_key": "17AB8342"
    },
    "result": "Failed",
    "failure_reason": "",
    "signature":"<B64>"
}
"""
class SKLogEntry:
    caller_types = ['INSTANCE', 'LAMBDA']
    _sign_function = None

    def __init__(self, caller_vpc):
        self._vpcid = caller_vpc
        self._event = {
            'event_version': 1,
            'vpc_op_seq_num': 0,
            'vpc_id': caller_vpc,
            'op_start': f'{datetime.utcnow().isoformat()}Z',
            'op_end': None,
            'caller': {
                'type': None,
                'id': None,
                'ip': None,
                'aws_account_id': None
            },
            'call': {
                'name': None,
                'parameters': None
            },
            'result': 'Succeed',
            'failure_reason': None
        }
        self._finalized = False
        self._account_id_finder = Thread(target=self._find_account_id_from_vpc, args=(caller_vpc,))
        self._account_id_finder.start()
        self._account_id_finder_ok = False
        self._signed = False
        self._json = None
        self._data_md5_b64 = None
        self._internode_lock = etcd.Lock(etcd_client, self._vpcid)
        self._destinations = [
            S3Sender(boto3.resource('s3', region_name=AWS_DEFAULT_REGION).Bucket(audit_bucket_name))
        ]

    @classmethod
    def set_sign_function(cls, f):
        cls._sign_function = f

    @property
    def vpc_id(self):
        return self._vpcid

    @property
    def vpc_op_seq_num(self):
        return self._event['vpc_op_seq_num']

    @property
    def data_to_send(self):
        assert self._signed
        if self._json is None:
            self._json = json.dumps(self._event).encode()
        return self._json

    @property
    def data_md5_b64(self):
        assert self._signed
        if self._data_md5_b64 is None:
            self._data_md5_b64 = bin_to_b64(md5(self.data_to_send).digest())
        return self._data_md5_b64

    def register_s3_destination(self, role_arn, bucket_name):
        assumed_role = sts_client.assume_role(
            RoleArn = role_arn,
            RoleSessionName = 'SovereignKeyApi',
            DurationSeconds = 900
        )
        creds = assumed_role['Credentials']
        self._destinations.append(
            S3Sender(
                boto3.resource('s3',
                    aws_access_key_id = creds['AccessKeyId'],
                    aws_secret_access_key = creds['SecretAccessKey'],
                    aws_session_token = creds['SessionToken'],
                    region_name=AWS_DEFAULT_REGION
                ).Bucket(bucket_name)
            )
        )

    def fail(self, reason):
        assert not self._finalized
        self._event['result'] = "Failed"
        self._event['failure_reason'] = reason

    def set_caller_account_id(self, caller_account_id):
        assert not self._finalized
        self._event['caller']['aws_account_id'] = caller_account_id

    def set_caller(self, caller_type, caller_id, caller_ip):
        assert not self._finalized
        assert caller_type in self.__class__.caller_types, f'Unsupported caller type {caller_type}'
        self._event['caller']['type'] = caller_type
        self._event['caller']['id'] = caller_id
        self._event['caller']['ip'] = caller_ip

    def set_call(self, name, parameters):
        assert not self._finalized
        self._event['call']['name'] = name
        self._event['call']['parameters'] = parameters

    def _find_account_id_from_vpc(self, caller_vpc):
        vpc_infos_table = boto3.resource('dynamodb').Table(vpc_infos_table_name)
        r = vpc_infos_table.get_item(
            Key={
                'VPCID': caller_vpc
            },
            ProjectionExpression='RemoteRoleARN,AuditBucketName',
            ReturnConsumedCapacity='NONE'
        )
        # Should never happen
        if 'Item' not in r:
            raise Exception('Could not find VPC')
        role_arn = r['Item']['RemoteRoleARN']
        # RoleARN: arn:${Partition}:iam::${Account}:role/${RoleNameWithPath}
        account_id = role_arn.split(':')[4]
        self.set_caller_account_id(account_id)

        # If an audit bucket is present, add it
        if 'AuditBucketName' in r['Item']:
            self.register_s3_destination(role_arn, r['Item']['AuditBucketName'])

        # If an exception happened before that, this flag will not be set to True
        self._account_id_finder_ok = True

    # Verify the object is ready to be signed
    def _validate(self):
        if self._account_id_finder is not None: self._account_id_finder.join()
        assert self._event['vpc_id'] is not None, 'vpc_id is None'
        assert self._event['caller']['type'] is not None, 'caller.type is None'
        assert self._event['caller']['id'] is not None, 'caller.id is None'
        assert self._event['caller']['ip'] is not None, 'caller.ip is None'
        assert self._event['caller']['aws_account_id'] is not None, 'caller.aws_account_id is None'
        assert self._event['call']['name'] is not None, 'call.name is None'
        assert self._event['call']['parameters'] is not None, 'call.parameters is None'
        assert self._event['op_start'] is not None, 'op_start is None'
        assert self._event['op_end'] is not None, 'op_end is None'
        assert self._account_id_finder_ok, 'account_id_finder failed'
        self._finalized = True

    def _set_sequence(self):
        try:
            self._event['vpc_op_seq_num'] = int(etcd_client.read(f'/log_sequences/{self._vpcid}').value)
        except etcd.EtcdKeyNotFound:
            etcd_client.write(f'/log_sequences/{self._vpcid}', 1)
            self._event['vpc_op_seq_num'] = 1
        logger.debug(f"Log sequence number is {self._event['vpc_op_seq_num']}")

    """
    Serialization of the JSON/Dictionnary for signature
    Rules:
     - Numbers are encoded as string, so 34 is "34"
     - String are encoded in lower-case UTF8 without ending \\0
     - None/null are the empty string
     - Each dictionnary value is encoded as "path.to.value=value"
     - those are separated by a single \\n and sorted by alphanumeric order
     - "signature" is not part of the signature

     This dictionnary:

    {
        "event_version": 1,
        "vpc_op_seq_num": 34,
        "vpc_id": "vpc-1234567890abcdef",
        "op_start": "2021-06-05T13:44:39.390805Z",
        "op_end": "2021-06-05T13:44:44.394534Z",
        "caller":{
            "type": "INSTANCE",
            "id": "i-1234567890abcdef",
            "ip": "10.42.12.13",
            "aws_account_id": "123456789012"
        },
        "call": "decrypt-secret",
        "call_parameters":{
            "instance_id": "i-1234567890abcdef",
            "volume_uuid": "39331fb1-f6b0-4a1f-b873-3490d3f1e491",
            "rsa_wrapping_key": "17AB8342"
        },
        "result": "Failed",
        "failure_reason": "",
        "signature":"<B64>"
    }

    is therefore encoded as the string:

    "call.name=decrypt-secret
    call.parameters.instance_id=i-1234567890abcdef
    call.parameters.rsa_wrapping_key=17ab8342
    call.parameters.volume_uuid=39331fb1-f6b0-4a1f-b873-3490d3f1e491
    caller.aws_account_id=123456789012
    caller.id=i-1234567890abcdef
    caller.ip=10.42.12.13
    caller.type=instance
    event_version=1
    failure_reason=
    op_end=2021-06-05T13:44:44.394534Z
    op_start=2021-06-05T13:44:39.390805Z
    result=succeed
    vpc_id=vpc-1234567890abcdef
    vpc_op_seq_num=34"

    and the signature is performed on the UTF8 binary representation of this string

    """
    def _serialize(self):
        def serialize_dict(d):
            for k, v in d.items():
                if isinstance(v, int):
                    yield f'{k}={v}'
                elif v is None:
                    yield f'{k}='
                elif isinstance(v, str):
                    yield f'{k}={v.lower()}'
                elif isinstance(v, dict):
                    for s in serialize_dict(v):
                        yield f'{k}.{s}'
        if 'signature' in self._event:
            del self._event['signature']
        tmp = list(serialize_dict(self._event))
        tmp.sort()
        return '\n'.join(tmp).encode()

    def _sign(self):
        logger.debug("Signing the audit log message")
        blob_to_sign = self._serialize()
        der_sig = self.__class__._sign_function(blob_to_sign)
        self._event['signature'] = bin_to_b64(der_sig)
        self._signed = True

    def _send(self):
        logger.info(f"Audit log message: {self.data_to_send}")
        logger.debug(f"Sending the audit log message to {len(self._destinations)} destination(s)")
        for dst in self._destinations:
            dst.send(self)

    def _commit_next_sequence(self):
        current = self._event['vpc_op_seq_num']
        next_seq = current + 1
        logger.debug(f"Commiting next log sequence number: {next_seq}")
        etcd_client.write(f'/log_sequences/{self._vpcid}', next_seq, prevValue = current)

    def __enter__(self):
        return self

    def _commit(self):
        self._event['op_end'] = f'{datetime.utcnow().isoformat()}Z'
        self._validate()
        # As a safetly mesure, the lock will be limited to 30 seconds
        # Else a really bad application restart timing could lock a specific VPC forever
        self._internode_lock.acquire(blocking=True, lock_ttl=30)
        try:
            self._set_sequence()
            self._sign()
            self._send()
            self._commit_next_sequence()
        finally:
            self._internode_lock.release()

    def __exit__(self, type_, value, traceback):
        if type_ is not None:
            if type_ == HTTPError:
                self.fail(value.message)
            else:
                self.fail('Internal API error')
        self._commit()
        return None
