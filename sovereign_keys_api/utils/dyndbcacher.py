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

import boto3
from datetime import datetime
from threading import Lock

class DynamoDBInfoTableCache:
    def __init__(self, table_name, ttl=900):
        self._table = boto3.resource('dynamodb').Table(table_name)
        self._ttl = ttl
        self._cache = {}
        self._boto3_client_lock = Lock()

    def get_info_item(self, vpc_id):
        cache_entry = self._cache.get(vpc_id)
        if cache_entry and cache_entry['expiration'] > datetime.utcnow().timestamp():
            return cache_entry['object']

        # We only protect the boto call itself because it is not thread-safe
        # We *may* endup calling table.get_item twice under some race condition
        # but it would just be a few milliseconds wasted
        # In exchange, we will not lock at all most of the time as soon as the
        # item is in the cache so we consider it worth it in the end.
        with self._boto3_client_lock:
            r = self._table.get_item(
                Key={'VPCID': vpc_id},
                ProjectionExpression='RemoteRoleARN,AuditBucketName,EktName',
                ReturnConsumedCapacity='NONE'
            )

        # Should never happen
        if 'Item' not in r:
            raise Exception('Could not find VPC')
        item = r['Item']
        self._cache[vpc_id] = {
            'object': item,
            'expiration': datetime.utcnow().timestamp() + self._ttl
        }
        return item
