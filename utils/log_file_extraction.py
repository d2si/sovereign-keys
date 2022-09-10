# Copyright 2022 Devoteam Revolve (D2SI SAS)
# This file is part of `Sovereign Keys`.
#
# `Sovereign Keys` is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# `Sovereign Keys` is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with `Sovereign Keys`. If not, see <http://www.gnu.org/licenses/>.

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
    "call": {
        "name": "decrypt-secret",
        "parameters":{
            "instance_id": "i-1234567890abcdef",
            "volume_uuid": "39331fb1-f6b0-4a1f-b873-3490d3f1e491",
            "rsa_wrapping_key": "17AB8342"
        }
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
def serialize(log_object):
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
    if 'signature' in log_object:
        del log_object['signature']
    tmp = list(serialize_dict(log_object))
    tmp.sort()
    return '\n'.join(tmp).encode()

import base64
def b64_to_bin(b64_str):
    return base64.standard_b64decode(b64_str)

import json
def process_log_file(filename):
    # Open the log and load the json
    with open(filename, 'r') as f:
        log_obj = json.load(f)

    # Get the signature blob
    sig_blob = b64_to_bin(log_obj['signature'])
    # Get the serialized blob
    ser_blob = serialize(log_obj)

    # Write files
    ser_filename = f"{filename}.serialized"
    print(f"Creating {ser_filename}")
    with open(ser_filename, 'wb') as f:
        f.write(ser_blob)
    sig_filename = f"{filename}.serialized.sig"
    print(f"Creating {sig_filename}")
    with open(sig_filename, 'wb') as f:
        f.write(sig_blob)

import argparse
if __name__ == "__main__":
    # execute only if run as a script
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile", help="the logfile to serialize and extract the signture from", type=str)
    args = parser.parse_args()
    process_log_file(args.logfile)
