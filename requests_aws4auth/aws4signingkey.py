"""
Provides AWS4SigningKey class for generating Amazone Web Services
authentication version 4 signing keys.

"""

# Licensed under the MIT License:
# http://opensource.org/licenses/MIT


from __future__ import unicode_literals

import hmac
import hashlib
from datetime import datetime
from .six import text_type


class AWS4SigningKey:
    """
    AWS signing key. Used to sign AWS authentication strings.

    The access key is not stored in the object after instantiation.

    Methods:
    generate_key() -- Generate AWS4 Signing Key string.
    sign_sha256()  -- Generate SHA256 HMAC signature, encoding message to bytes
                      if required.

    Attributes:
    region   -- AWS region the key is scoped for
    service  -- AWS service the key is scoped for
    amz_date -- Initial date key is scoped for
    scope    -- The AWS scope string for this key, calculated from the above
                attributes.
    key      -- The signing key string itself

    """

    def __init__(self, access_key, region, service, date=None):
        """
        >>> AWS4SigningKey(access_key, region, service[, date])

        access_key -- This is your AWS access key
        region     -- The region you're connecting to, as per list at
                      http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
                      e.g. us-east-1. For services which don't require a
                      region (e.g. IAM), use us-east-1.
        service    -- The name of the service you're connecting to, as per
                      endpoints at:
                      http://docs.aws.amazon.com/general/latest/gr/rande.html
                      e.g. elasticbeanstalk
        date       -- 8-digit date of the form YYYYMMDD. This is the starting
                      date for the signing key's validity, signing keys are
                      valid for 7 days from this date.  If date is not supplied
                      the current date is used.

        All arguments should be supplied as strings.

        Once instantiated the signing key string is stored in the key
        attribute. The access key is not stored in the object after
        instantiation.

        """

        self.region = region
        self.service = service
        self.amz_date = date or datetime.utcnow().strftime('%Y%m%d')
        self.scope = '{}/{}/{}/aws4_request'.format(
                                            self.amz_date,
                                            self.region,
                                            self.service)
        self.key = self.generate_key(access_key, self.region,
                                     self.service, self.amz_date)

    @classmethod
    def generate_key(cls, access_key, region, service, amz_date,
                     intermediate=False):
        """
        Generate the signing key string as bytes.

        If intermediate is set to True, returns a 4-tuple containing the key
        and the intermediate keys:

        ( signing_key, date_key, region_key, service_key )

        The intermediate keys can be used for testing against example from
        Amazon.

        """
        init_key = ('AWS4' + access_key).encode('utf-8')
        date_key = cls.sign_sha256(init_key, amz_date)
        region_key = cls.sign_sha256(date_key, region)
        service_key = cls.sign_sha256(region_key, service)
        key = cls.sign_sha256(service_key, 'aws4_request')
        if intermediate:
            return (key, date_key, region_key, service_key)
        else:
            return key

    @staticmethod
    def sign_sha256(key, msg):
        """
        Generate an SHA256 HMAC, encoding msg to UTF-8 if not
        already encoded.

        key -- signing key. bytes.
        msg -- message to sign. unicode or bytes.

        """
        if isinstance(msg, text_type):
            msg = msg.encode('utf-8')
        return hmac.new(key, msg, hashlib.sha256).digest()
