"""
Provides AWS4Auth class for handling Amazon Web Services version 4
authentication with the Requests module.

"""

# Licensed under the MIT License:
# http://opensource.org/licenses/MIT


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
    Requests authentication class for providing AWS version 4 authentication
    for HTTP requests.

    Provides basic authentication for regions and services listed at:
    http://docs.aws.amazon.com/general/latest/gr/rande.html

    The following services do not support AWS auth version 4 and are not usable
    with this package:
        * Simple Email Service (SES)' - AWS auth v3 only
        * Simple Workflow Service - AWS auth v3 only
        * Import/Export - AWS auth v2 only
        * SimpleDB - AWS auth V2 only
        * DevPay - AWS auth v1 only
        * Mechanical Turk - has own signing mechanism

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

    Class attributes
    ----------------

    AWS4Auth.access_id   -- the access ID supplied to the instance
    AWS4Auth.region      -- the AWS region for the instance
    AWS4Auth.service     -- the endpoint code for the service for this instance
    AWS4Auth.signing_key -- instance of AWS4SigningKey used for this instance,
                            either generated from the supplied parameters or
                            supplied directly on the command line

   """

    default_include_headers = ['host', 'content-type', 'x-amz-*']

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
        signing_key - An AWS4SigningKey instance.

        All arguments except signing_key should be supplied as strings.

        """
        l = len(args)
        if l not in [2, 4]:
            msg = 'AWS4Auth() takes 2 or 4 arguments, {} given'.format(l)
            raise TypeError(msg)
        self.access_id = args[0]
        if isinstance(args[1], AWS4SigningKey) and len(args) == 2:
            # instantiate from signing key
            key = args[1]
            self.region = key.region
            self.service = key.service
            self.signing_key = key
        elif len(args) == 4:
            # instantiate from args
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
            self.include_hdrs = self.default_include_headers
        AuthBase.__init__(self)

    def __call__(self, req):
        """
        Interface used by Requests module to apply authentication to HTTP
        requests.

        Add x-amz-content-sha256 and Authorization headers to the request. Add
        x-amz-date header to request if not already present.

        If request body is not already encoded to bytes, encode to charset
        specified in Content-Type header, or UTF-8 if not specified.

        req -- Requests PreparedRequest object

        """
        if hasattr(req, 'body') and req.body is not None:
            self.encode_body(req)
        else:
            req.body = b''
        content_hash = hashlib.sha256(req.body)
        req.headers['x-amz-content-sha256'] = content_hash.hexdigest()
        if 'X-Amz-Date' not in req.headers:
            timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
            req.headers['X-Amz-Date'] = timestamp
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

        req -- Requests PreparedRequest object

        """
        if isinstance(req.body, text_type):
            split = req.headers.get('content-type', 'text/plain').split(';')
            if len(split) == 2:
                ct, cs = split
                cs = cs.split('=')[1]
                req.body = req.body.encode(cs)
            else:
                ct = split[0]
                if (ct == 'application/x-www-form-urlencoded' or
                        'x-amz-' in ct):
                    req.body = req.body.encode()
                else:
                    req.body = req.body.encode('utf-8')
                    req.headers['content-type'] = ct + '; charset=utf-8'

    @classmethod
    def get_canonical_request(cls, req, cano_headers, signed_headers):
        """
        Create the AWS authentication Canonical Request string.

        req            -- Requests PreparedRequest object. Should already
                          include an x-amz-content-sha256 header
        cano_headers   -- Canonical Headers section of Canonical Request, as
                          returned by get_canonical_headers()
        signed_headers -- Signed Headers, as returned by
                          get_canonical_headers()

        """
        url = urlparse(req.url)
        path = cls.amz_cano_path(url.path)
        # AWS handles "extreme" querystrings differently to urlparse
        # (see post-vanilla-query-nonunreserved test in aws_testsuite)
        split = req.url.split('?', 1)
        qs = split[1] if len(split) == 2 else ''
        qs = cls.amz_cano_querystring(qs)
        payload_hash = req.headers['x-amz-content-sha256']
        req_parts = [req.method.upper(), path, qs, cano_headers,
                     signed_headers, payload_hash]
        cano_req = '\n'.join(req_parts)
        return cano_req

    @classmethod
    def get_canonical_headers(cls, req, include=None):
        """
        Generate the Canonical Headers section of the Canonical Request.

        Return the Canonical Headers and the Signed Headers strs as a tuple
        (canonical_headers, signed_headers).

        req     -- Requests PreparedRequest object
        include -- List of headers to include in the canonical and signed
                   headers. It's primarily included to allow testing against
                   specific examples from Amazon. If omitted or None it
                   includes host, content-type and any header starting 'x-amz-'
                   except for x-amz-client context, which appears to break
                   mobile analytics auth if included. Except for the
                   x-amz-client-context exclusion these defaults are per the
                   AWS documentation.

        """
        if include is None:
            include = cls.default_include_headers
        include = [x.lower() for x in include]
        headers = req.headers.copy()
        # Temporarily include the host header - AWS requires it to be included
        # in the signed headers, but Requests doesn't include it in a
        # PreparedRequest
        if 'host' not in headers:
            headers['host'] = urlparse(req.url).netloc
        # Aggregate for upper/lowercase header name collisions in header names,
        # AMZ requires values of colliding headers be concatenated into a
        # single header with lowercase name.  Although this is not possible with
        # Requests, since it uses a case-insensitive dict to hold headers, this
        # is here just in case you duck type with a regular dict
        cano_headers_dict = {}
        for hdr, val in headers.items():
            hdr = hdr.strip().lower()
            val = cls.amz_norm_whitespace(val).strip()
            if (hdr in include or '*' in include or
                    ('x-amz-*' in include and hdr.startswith('x-amz-') and not
                    hdr == 'x-amz-client-context')):
                vals = cano_headers_dict.setdefault(hdr, [])
                vals.append(val)
        # Flatten cano_headers dict to string and generate signed_headers
        cano_headers = ''
        signed_headers_list = []
        for hdr in sorted(cano_headers_dict):
            vals = cano_headers_dict[hdr]
            val = ','.join(sorted(vals))
            cano_headers += '{}:{}\n'.format(hdr, val)
            signed_headers_list.append(hdr)
        signed_headers = ';'.join(signed_headers_list)
        return (cano_headers, signed_headers)

    @staticmethod
    def get_sig_string(req, cano_req, scope):
        """
        Generate the AWS4 auth string to sign for the request.

        req      -- Requests PreparedRequest object. This should already
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

        Not documented anywhere, determined from aws4_testsuite examples.

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
        Parse and format querystring as per AWS4 auth requirements.

        Perform percent quoting as needed.

        qs -- querystring

        """
        safe_qs_amz_chars = '&=+'
        safe_qs_unresvd = '-_.~'
        # If Python 2, switch to working entirely in str
        # as quote() has problems with Unicode
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
