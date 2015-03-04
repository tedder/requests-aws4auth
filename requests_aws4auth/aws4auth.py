"""
Provides AWS4Auth class for handling Amazon Web Services version 4
authentication with the requests module.

"""

from __future__ import unicode_literals

import hmac
import hashlib
import posixpath
import re
import shlex
from datetime import datetime

try:
    from urllib.parse import urlparse, parse_qs, quote, unquote
except ImportError:
    from urlparse import urlparse, parse_qs
    from urllib import quote, unquote

from requests.auth import AuthBase
from .six import PY2, text_type, u
from .aws4signingkey import AWS4SigningKey


class AWS4Auth(AuthBase):
    """
    requests authentication class for providing AWS version 4 authentication
    for HTTP requests. Provides basic authentication for all regions and
    services listed at http://docs.aws.amazon.com/general/latest/gr/rande.html

    You can reuse AWS4Auth instances to sign as many requests as you need.

    Basic usage
    -----------

    >>> import requests
    >>> from requests_aws4auth import AWS4Auth
    >>> auth = AWS4Auth('<ACCESS ID>', '<ACCESS KEY>', 'eu-west-1', 's3')
    >>> endpoint = 'http://s3-eu-west-1.amazonaws.com'
    >>> response = requests.get(endpoint, auth=auth)
    >>> response.status_code
    200

    This example lists your buckets in the eu-west-1 region of the Amazon S3
    service.

    """

    def __init__(self, *args, **kwargs):
        """
        AWS4Auth instances can be created by supplying scoping parameters
        directly or by using a pre-generated signing key:

        >>> auth = AWS4Auth(access_id, access_key, region, service)

          or

        >>> auth = AWS4Auth(access_id, signing_key)

        access_id  -- This is your AWS access ID
        access_key -- This is your AWS access key
        region     -- The region you're connecting to, as per this list at
                      http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
                      e.g. us-east-1. For services which don't require a region
                      (e.g. IAM), use us-east-1.
        service    -- The name of the service you're connecting to, as per
                      endpoints at:
                      http://docs.aws.amazon.com/general/latest/gr/rande.html
                      e.g. elasticbeanstalk.
        signing_key - A signing key as created by AWS4SigningKey.

        All arguments should be supplied as strings.

        """

        i = len(args)
        if i not in [2, 4]:
            msg = 'AWS4Auth() takes 2 or 4 arguments, {} given'.format(i)
            raise TypeError(msg)
        self.access_id = args[0]
        if isinstance(args[1], AWS4SigningKey) and len(args) == 2:
            # instantiating from signing key
            key = args[1]
            self.region = key.region
            self.service = key.service
            self.signing_key = key
        elif len(args) == 4:
            # instantiating from args
            access_key = args[1]
            self.region = args[2]
            self.service = args[3]
            self.signing_key = AWS4SigningKey(access_key,
                                              self.region,
                                              self.service)
        else:
            raise TypeError()
        if 'include_hdrs' in kwargs:
            self.include_hdrs = kwargs[str('include_hdrs')]
        else:
            self.include_hdrs = ['*']
        AuthBase.__init__(self)

    def __call__(self, req, timestamp=None):
        """
        Interface used by requests module to apply authentication to HTTP
        requests.

        Add x-amz-date, x-amz-content-sha256 and Authorization headers to the
        request.

        If request body is not already encoded to bytes, encode to charset
        specified in Content-Type header, or UTF-8 if not specified.

        req -- requests PreparedRequest object

        """
        timestamp = timestamp or datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        if hasattr(req, 'body') and req.body is not None:
            self.encode_body(req)
        else:
            req.body = b''
        content_hash = hashlib.sha256(req.body).hexdigest()
        req.headers['x-amz-content-sha256'] = content_hash
        req.headers['x-amz-date'] = timestamp
        result = self.get_canonical_headers(req, self.include_hdrs)
        cano_headers, signed_headers = result
        cano_req = self.get_canonical_request(req, cano_headers,
                                              signed_headers)
        sig_string = self.get_sig_string(req, cano_req, self.signing_key.scope)
        sig_string = sig_string.encode('utf-8')
        hsh = hmac.new(self.signing_key.key, sig_string, hashlib.sha256)
        sig = hsh.hexdigest()
        auth_str = 'AWS4-HMAC-SHA256 '
        auth_str += 'Credential={}/{}, '.format(self.access_id,
                                                self.signing_key.scope)
        auth_str += 'SignedHeaders={}, '.format(signed_headers)
        auth_str += 'Signature={}'.format(sig)
        req.headers['Authorization'] = auth_str
        return req

    @staticmethod
    def encode_body(req):
        """
        Encode body of request to bytes and update content-type if required.

        If the body of req is unicode then encode to the charset found in
        content-type header if present, otherwise UTF-8, or ASCII if
        content-type is application/x-www-form-urlencoded. If encoding to UTF-8
        then add charset to content-type. Modifies req directly, does not
        return a modified copy.

        req: requests PreparedRequest object

        """
        if isinstance(req.body, text_type):
            split = req.headers.get('content-type', 'text/plain').split(';')
            if len(split) == 2:
                ct, cs = split
                cs = cs.split('=')[1]
                req.body = req.body.encode(cs)
            else:
                ct = split[0]
                if ct == 'application/x-www-form-urlencoded':
                    req.body = req.body.encode()
                else:
                    req.body = req.body.encode('utf-8')
                    req.headers['content-type'] = ct + '; charset=utf-8'

    @classmethod
    def get_canonical_request(cls, req, cano_headers, signed_headers):
        """
        Create the AWS authentication Canonical Request string.

        req            -- requests PreparedRequest object. Should already
                          include an x-amz-content-sha256 header
        cano_headers   -- Canonical Headers section of Canonical Request, as
                          returned by get_canonical_headers()
        signed_headers -- Signed Headers, as returned by
                          get_canonical_headers()

        """
        url = urlparse(req.url)
        path = cls.amz_cano_path(url.path)
        split = req.url.split('?', 1)
        qs = split[1] if len(split) == 2 else ''
        qs = cls.amz_cano_querystring(qs)
        req_parts = [req.method.upper(), path, qs, cano_headers,
                     signed_headers, req.headers['x-amz-content-sha256']]
        cano_req = '\n'.join(req_parts)
        return cano_req

    @classmethod
    def get_canonical_headers(cls, req, include=None):
        """
        Generate the Canonical Headers section of the Canonical Request.

        Return the Canonical Headers and the Signed Headers as a tuple.

        req     -- requests PreparedRequest object
        include -- List of headers to include in the canonical and signed
                   headers. By default it includes all headers, which is fine
                   for AWS. It's primarily included to allow testing against
                   specific examples from Amazon.

        """
        if include is None:
            include = ['*']
        include = [x.lower() for x in include]
        headers = req.headers
        # need to aggregate for upper/lowercase header name collisions in
        # header names, AMZ requires values of colliding headers be
        # concatenated into a single header with lowercase name
        cano_headers_dict = {}
        for hdr, val in headers.items():
            hdr = hdr.strip().lower()
            val = cls.amz_norm_whitespace(val).strip()
            if hdr in include or '*' in include:
                vals = cano_headers_dict.setdefault(hdr.lower(), [])
                vals.append(val)
        if 'host' in include and 'host' not in cano_headers_dict:
            cano_headers_dict['host'] = urlparse(req.url).netloc
        # flatten cano_headers dict to string
        cano_headers = ''
        signed_headers_list = []
        for hdr in sorted(cano_headers_dict):
            val = ','.join(cano_headers_dict[hdr])
            cano_headers += ':'.join([hdr, val]) + '\n'
            signed_headers_list.append(hdr)
        signed_headers = ';'.join(signed_headers_list)
        return (cano_headers, signed_headers)

    @staticmethod
    def get_sig_string(req, cano_req, scope):
        """
        Generate the AWS4 auth string to sign for the request.

        req      -- requests PreparedRequest object. This should already
                    include an x-amz-date header.
        cano_req -- The Canonical Request, as returned by
                    get_canonical_request()

        """
        amz_date = req.headers['x-amz-date']
        hsh = hashlib.sha256(cano_req.encode())
        sig_items = ['AWS4-HMAC-SHA256', amz_date, scope, hsh.hexdigest()]
        sig_string = '\n'.join(sig_items)
        return sig_string

    @staticmethod
    def amz_cano_path(path):
        """
        Generate the canonical path as per AWS4 auth requirements.

        path -- request path

        """
        qs = ''
        fixed_path = path
        if '?' in fixed_path:
            fixed_path, qs = fixed_path.split('?', 1)
        fixed_path = posixpath.normpath(fixed_path)
        fixed_path = re.sub('/+', '/', fixed_path)
        if path.endswith('/') and not fixed_path.endswith('/'):
            fixed_path += '/'
        full_path = fixed_path
        if qs:
            full_path = '?'.join((full_path, qs))
        return full_path

    @staticmethod
    def amz_cano_querystring(qs):
        """
        Parse and format qeurystring as per AWS4 auth requirements.

        Perform percent quoting as needed.

        qs -- querystring

        """
        safe_qs_amz_chars = '&=+'
        safe_qs_unresvd = '-_.~'
        # If Python 2 switch to working entirely in str
        # as quote() has problems with unicode
        if PY2:
            qs = qs.encode('utf-8')
            safe_qs_amz_chars = safe_qs_amz_chars.encode()
            safe_qs_unresvd = safe_qs_unresvd.encode()
        qs = unquote(qs)
        space = b' ' if PY2 else ' '
        qs = qs.split(space)[0]
        qs = quote(qs, safe=safe_qs_amz_chars)
        qs_items = {}
        for name, vals in parse_qs(qs, keep_blank_values=True).items():
            name = quote(name, safe=safe_qs_unresvd)
            vals = [quote(val, safe=safe_qs_unresvd) for val in vals]
            qs_items[name] = vals
        qs_strings = []
        for name, vals in qs_items.items():
            for val in vals:
                qs_strings.append('='.join([name, val]))
        qs = '&'.join(sorted(qs_strings))
        if PY2:
            qs = unicode(qs)
        return qs

    @staticmethod
    def amz_norm_whitespace(text):
        """
        Replace runs of whitespace with a single space.

        Ignore text enclosed in quotes.

        """
        return ' '.join(shlex.split(text, posix=False))
