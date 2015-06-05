import json
import copy
import hmac
import base64
from hashlib import sha256
from datetime import datetime, timedelta
import uuid

from django.shortcuts import render
from django.views.generic import View
from django.conf import settings
from django.http import HttpResponse

# Create your views here.

class S3SignView(View):
    access_key    = settings.AWS_ACCESS_KEY
    secret_key    = settings.AWS_SECRET_KEY
    bucket        = settings.S3_BUCKET
    upload_prefix = 'avatars/'
    region        = 'us-east-1'
    upload_url    = 'http://{0}.s3.amazonaws.com/'.format(bucket)

    default_policy =  { 
        "expiration": "YYYY-MM-DDTHH:MM:SS.000Z",
        "conditions": [
            {"bucket": bucket},
            ["starts-with", "$key", upload_prefix],
            {"acl": "public-read"},            
            ["starts-with", "$Content-Type", ""],            
            {"x-amz-algorithm": "AWS4-HMAC-SHA256"},

            # these are added programatically as they need the current time
            # {"x-amz-credential": "<AWS_ACCESS_KEY>/YYYMMDD/<region>/s3/aws4_request" },
            # {"x-amz-date": "YYYYMMDDTHHMMSSZ" }
        ]
    }

    def get(self, request):
        now    = datetime.utcnow()
        expire = now + timedelta(minutes=5)

        kwargs = request.GET

        name_parts = kwargs['file_name'].split('.')
        # replace name with a random to avoid collisions
        name_parts[ 0 ] = uuid.uuid4().hex
        key = self.upload_prefix + '.'.join(name_parts)
        content_type = kwargs['file_type']

        policy = copy.deepcopy(self.default_policy)
        policy['expiration']  = expire.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        
        date = {'x-amz-date': expire.strftime('%Y%m%dT%H%M%SZ') }
        policy['conditions'].append( date )
        
        credential = {'x-amz-credential': '{0}/{1}/{2}/s3/aws4_request'.format(self.access_key, expire.strftime('%Y%m%d'), self.region)}
        policy['conditions'].append( credential)
        
        base64_policy = base64.b64encode( json.dumps(policy) )

        data = [
            { 'key': key },
            { 'policy': base64_policy },
            { 'x-amz-signature': self._hmac_sha256( self._get_signing_key(expire), base64_policy ).hexdigest() },            
            { 'x-amz-algorithm': 'AWS4-HMAC-SHA256' },
            { 'content-type': content_type },
            { 'acl': 'public-read' },            
            credential,
            date,            
        ]

        result = { 'data': data, 'post_url': self.upload_url, 'result_url': self.upload_url + key }
        return HttpResponse( json.dumps(result) )

    def _get_signing_key(self, date):
        hash1 = self._hmac_sha256('AWS4' + self.secret_key, date.strftime('%Y%m%d')).digest()
        hash2 = self._hmac_sha256(hash1, self.region).digest()
        hash3 = self._hmac_sha256(hash2, 's3').digest()
        hash4 = self._hmac_sha256(hash3, 'aws4_request').digest()

        return hash4

    @staticmethod
    def _hmac_sha256(key, msg):
        return hmac.new(key, msg.encode('utf-8'), sha256)