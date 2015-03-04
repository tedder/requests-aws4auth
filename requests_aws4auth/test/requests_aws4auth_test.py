#!/usr/bin/env python
# coding: utf-8

"""
Tests for requests-aws4auth package.

Two major tests are dependent on having a copy of the AWS4 testsuite available.
Because Amazon hasn't made the licensing conditions clear for this it's not
included in this source, but it is free to download.

Download the testsuite zip from here:
http://docs.aws.amazon.com/general/latest/gr/samples/aws4_testsuite.zip

Unzip the suite to a folder called aws4_testsuite in this test directory. You
can use another folder but you'll need to update the path in
AmzAws4TestSuite.__init__().

Without the test suite the rest of the tests will still run, but many edge
cases covered by the suite will be missed.

"""


from __future__ import unicode_literals

import sys
import os
import unittest
import re
import hashlib
import itertools
import requests
from datetime import datetime

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

sys.path = ['../../'] + sys.path
from requests_aws4auth import AWS4Auth
from requests_aws4auth.aws4signingkey import AWS4SigningKey
from requests_aws4auth.six import PY2


class SimpleNamespace:
    pass


class AmzAws4TestSuite:
    """
    Load and wrap files from the aws4_testsuite.zip test suite from Amazon.

    Test suite files are available from:
    http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html

    Methods:
    load_testsuite_data: Staticmethod. Loads the test suites file found at the
                         supplied path and returns a dict containing the data.

    Attributes:
    access_id:  The AWS access ID used by the test examples in the suite.
    access_key: The AWS secret access ID used by the test examples in the
                suite.
    region:     The AWS region used by the test examples in the suite.
    service:    The AWS service used by the test examples in the suite.
    date:       The datestring used by the test examples in the suite
    timestamp:  The timestamp used by the test examples in the suite
    path:       The path to the directory containing the test suite files.
    data:       A dict containing the loaded test file data. See
                documentation for load_testsuite_data() method for a
                description of the structure.

    """

    def __init__(self, path=None):
        self.access_id = 'AKIDEXAMPLE'
        self.access_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
        self.region = 'us-east-1'
        self.service = 'host'
        self.date = '20110909'
        self.timestamp = '20110909T233600Z'
        self.path = path or 'aws4_testsuite'
        self.data = self.load_testsuite_data(self.path)

    @staticmethod
    def load_testsuite_data(path):
        """
        Return test_suite dict containing grouped test file contents.

        Return dict is of the form:

            {'<file group name>': {'<extension>': content,
                                   '<extension>': content, ...},
             '<file group name>': {'<extension>': content,
                                   '<extension>': content, ...},
             ...
            }

        """
        if not os.path.exists(path):
            raise ValueError('Test Suite directory not found. Download the '
                             'test suite from here: http://docs.aws.amazon.com'
                             '/general/latest/gr/samples/aws4_testsuite.zip')
        files = sorted(os.listdir(path))
        if not files:
            raise ValueError('Test Suite directory empty. Download the test '
                             'suite from here: http://docs.aws.amazon.com/ge'
                             'neral/latest/gr/samples/aws4_testsuite.zip')
        grouped = itertools.groupby(files, lambda x: os.path.splitext(x)[0])
        data = {}
        for group_name, items in grouped:
            group = {}
            for item in items:
                filepath = os.path.join(path, item)
                file_ext = os.path.splitext(item)[1]
                if PY2:
                    with open(filepath) as f:
                        content = unicode(f.read(), encoding='utf-8')
                else:
                    with open(filepath, encoding='utf-8') as f:
                        content = f.read()
                group[file_ext] = content
            data[group_name] = group
        return data
try:
    amz_aws4_testsuite = AmzAws4TestSuite()
except ValueError:
    amz_aws4_testsuite = None


def request_from_text(text):
    """
    Construct a requests PreparedRequest using values provided in text.

    text should be a plaintext HTTP request, as defined in RFC7230.

    """
    lines = text.splitlines()
    match = re.search('^([a-z]+) (.*) (http/[0-9]\.[0-9])$', lines[0], re.I)
    method, path, version = match.groups()
    headers = {}
    for idx, line in enumerate(lines[1:], start=1):
        if not line:
            break
        hdr, val = [item.strip() for item in line.split(':', 1)]
        hdr = hdr.lower()
        vals = headers.get(hdr, [])
        vals.append(val)
        headers[hdr] = vals
    headers = {hdr: ','.join(sorted(vals)) for hdr, vals in headers.items()}
    check_url = urlparse(path)
    if check_url.scheme and check_url.netloc:
        # absolute URL in path
        url = path
    else:
        # otherwise need to try to construct url from path and host header
        url = ''.join(['http://' if 'host' in headers else '',
                       headers.get('host', ''),
                       path])
    body = '\n'.join(lines[idx+1:])
    req = requests.Request(method, url, headers=headers, data=body)
    return req.prepare()


class AWS4_SigningKey_Test(unittest.TestCase):

    def test_basic_instantiation(self):
        obj = AWS4SigningKey('access_key', 'region', 'service', 'date')
        self.assertEqual(obj.region, 'region')
        self.assertEqual(obj.service, 'service')
        self.assertEqual(obj.amz_date, 'date')
        self.assertEqual(obj.scope, 'date/region/service/aws4_request')

    def test_timestamp(self):
        test_timestamp = datetime.utcnow().strftime('%Y%m%d')
        obj = AWS4SigningKey('access_key', 'region', 'service')
        if obj.amz_date != test_timestamp:
            test_timestamp = datetime.utcnow().strftime('%Y%m%d')
        self.assertEqual(obj.amz_date, test_timestamp)

    def test_sign_sha256_unicode_msg(self):
        key = b'The quick brown fox jumps over the lazy dog'
        msg = ('Forsaking monastic tradition, twelve jovial friars gave up '
              'their vocation for a questionable existence on the flying '
              'trapeze')
        expected = [250, 103, 254, 220, 118, 118, 37, 81, 166, 41, 65, 14,
                    142, 77, 204, 122, 185, 19, 38, 15, 145, 249, 113, 69,
                    178, 30, 131, 244, 230, 190, 246, 23]
        hsh = AWS4SigningKey.sign_sha256(key, msg)
        hsh = [ord(x) for x in hsh] if PY2 else list(hsh)
        self.assertEqual(hsh, expected)

    def test_sign_sha256_bytes_msg(self):
        key = b'The quick brown fox jumps over the lazy dog'
        msg = (b'Forsaking monastic tradition, twelve jovial friars gave up '
               b'their vocation for a questionable existence on the flying '
               b'trapeze')
        expected = [250, 103, 254, 220, 118, 118, 37, 81, 166, 41, 65, 14,
                    142, 77, 204, 122, 185, 19, 38, 15, 145, 249, 113, 69,
                    178, 30, 131, 244, 230, 190, 246, 23]
        hsh = AWS4SigningKey.sign_sha256(key, msg)
        hsh = [ord(x) for x in hsh] if PY2 else list(hsh)
        self.assertEqual(hsh, expected)

    def test_signing_key_phases(self):
        """
        Using example data from:
        http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html

        """
        access_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
        region = 'us-east-1'
        service = 'iam'
        date = '20120215'
        # These are signing key, date_key, region_key and service_key
        # respectively
        expected_raw = (
            'f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d',
            '969fbb94feb542b71ede6f87fe4d5fa29c789342b0f407474670f0c2489e0a0d',
            '69daa0209cd9c5ff5c8ced464a696fd4252e981430b10e3d3fd8e2f197d7a70c',
            'f72cfd46f26bc4643f06a11eabb6c0ba18780c19a8da0c31ace671265e3c87fa')
        expected = []
        for hsh in expected_raw:
            hexen = re.findall('..', hsh)
            expected.append([int(x, base=16) for x in hexen])
        result = AWS4SigningKey.generate_key(access_key, region,
                                             service, date, intermediate=True)
        for i, hsh in enumerate(result):
            hsh = [ord(x) for x in hsh] if PY2 else list(hsh)
            self.assertEqual(hsh, expected[i], msg='Item number {}'.format(i))

    def test_generate_key(self):
        """
        Using example data from:
        http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

        """
        access_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
        region = 'us-east-1'
        service = 'iam'
        date = '20110909'
        expected = [152, 241, 216, 137, 254, 196, 244, 66, 26, 220, 82, 43,
                    171, 12, 225, 248, 46, 105, 41, 194, 98, 237, 21, 229,
                    169, 76, 144, 239, 209, 227, 176, 231]
        key = AWS4SigningKey.generate_key(access_key, region, service, date)
        key = [ord(x) for x in key] if PY2 else list(key)
        self.assertEqual(key, expected)

    def test_instantiation_generate_key(self):
        """
        Using example data from:
        http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

        """
        access_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
        region = 'us-east-1'
        service = 'iam'
        date = '20110909'
        expected = [152, 241, 216, 137, 254, 196, 244, 66, 26, 220, 82, 43,
                    171, 12, 225, 248, 46, 105, 41, 194, 98, 237, 21, 229,
                    169, 76, 144, 239, 209, 227, 176, 231]
        key = AWS4SigningKey(access_key, region, service, date).key
        key = [ord(x) for x in key] if PY2 else list(key)
        self.assertEqual(key, expected)


class AWS4Auth_Instantiate_Test(unittest.TestCase):

    def test_instantiate_from_args(self):
        test_timestamp = datetime.utcnow().strftime('%Y%m%d')
        auth = AWS4Auth('access_id', 'access_key', 'region', 'service')
        self.assertEqual(auth.access_id, 'access_id')
        self.assertEqual(auth.region, 'region')
        self.assertEqual(auth.service, 'service')
        self.assertIsInstance(auth.signing_key, AWS4SigningKey)
        self.assertEqual(auth.signing_key.region, 'region')
        self.assertEqual(auth.signing_key.service, 'service')
        if test_timestamp != auth.signing_key.amz_date:
            test_timestamp = datetime.utcnow().strftime('%Y%m%d')
        self.assertEqual(auth.signing_key.amz_date, test_timestamp)
        expected = '{}/region/service/aws4_request'.format(test_timestamp)
        self.assertEqual(auth.signing_key.scope, expected)

    def test_instantiate_from_signing_key(self):
        key = AWS4SigningKey('access_key', 'region', 'service', 'date')
        auth = AWS4Auth('access_id', key)
        self.assertEqual(auth.access_id, 'access_id')
        self.assertEqual(auth.region, 'region')
        self.assertEqual(auth.service, 'service')
        self.assertIsInstance(auth.signing_key, AWS4SigningKey)
        self.assertEqual(auth.signing_key.region, 'region')
        self.assertEqual(auth.signing_key.service, 'service')

    def test_func_signature_check(self):
        self.assertRaises(TypeError, AWS4Auth, tuple())
        self.assertRaises(TypeError, AWS4Auth, ('a',))
        self.assertRaises(TypeError, AWS4Auth, ('a', 'a'))
        self.assertRaises(TypeError, AWS4Auth, ('a', 'a', 'a'))
        self.assertRaises(TypeError, AWS4Auth, ('a', 'a', 'a', 'a', 'a'))


class AWS4Auth_EncodeBody_Test(unittest.TestCase):

    def setUp(self):
        self.req = SimpleNamespace()
        self.req.body = ''
        self.req.headers = {}

    def test_encode_body_unicode_to_bytes(self):
        self.req.body = u'hello'
        AWS4Auth.encode_body(self.req)
        self.assertEqual(self.req.body, b'\x68\x65\x6c\x6c\x6f')
        expected = 'text/plain; charset=utf-8'
        self.assertEqual(self.req.headers['content-type'], expected)

    def test_encode_body_utf8_string_to_bytes(self):
        self.req.body = u'☃'
        AWS4Auth.encode_body(self.req)
        self.assertEqual(self.req.body, b'\xe2\x98\x83')
        expected = 'text/plain; charset=utf-8'
        self.assertEqual(self.req.headers['content-type'], expected)

    def test_encode_body_bytes(self):
        text = b'hello'
        self.req.body = text
        AWS4Auth.encode_body(self.req)
        self.assertEqual(self.req.body, text)
        self.assertEqual(self.req.headers, {})


class AWS4Auth_GetCanonicalHeaders_Test(unittest.TestCase):

    def setUp(self):
        self.req = SimpleNamespace
        self.req.headers = {}

    def test_headers_amz_example(self):
        """
        Using example from:
        http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

        """
        hdr_text = [
            'host:iam.amazonaws.com',
            'Content-type:application/x-www-form-urlencoded; charset=utf-8',
            'My-header1:    a   b   c ',
            'x-amz-date:20120228T030031Z',
            'My-Header2:    "a   b   c"']
        headers = dict([item.split(':') for item in hdr_text])
        req = requests.Request('GET',
                               'http://iam.amazonaws.com',
                               headers=headers)
        req = req.prepare()
        include = list(req.headers)
        result = AWS4Auth.get_canonical_headers(req, include=include)
        cano_headers, signed_headers = result
        expected = [
            'content-type:application/x-www-form-urlencoded; charset=utf-8',
            'host:iam.amazonaws.com',
            'my-header1:a b c',
            'my-header2:"a   b   c"',
            'x-amz-date:20120228T030031Z']
        expected = '\n'.join(expected) + '\n'
        self.assertEqual(cano_headers, expected)
        expected = 'content-type;host;my-header1;my-header2;x-amz-date'
        self.assertEqual(signed_headers, expected)


class AWS4Auth_GetCanonicalRequest_Test(unittest.TestCase):

    def test_amz1(self):
        """
        Using example data selected from:
        http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

        """
        req_text = [
            'POST https://iam.amazonaws.com/ HTTP/1.1',
            'Host: iam.amazonaws.com',
            'Content-Length: 54',
            'Content-Type: application/x-www-form-urlencoded',
            'X-Amz-Date: 20110909T233600Z',
            '',
            'Action=ListUsers&Version=2010-05-08']
        req = request_from_text('\n'.join(req_text))
        AWS4Auth.encode_body(req)
        hsh = hashlib.sha256(req.body)
        req.headers['x-amz-content-sha256'] = hsh.hexdigest()
        include_hdrs = ['host', 'content-type', 'x-amz-date']
        result = AWS4Auth.get_canonical_headers(req, include=include_hdrs)
        cano_headers, signed_headers = result
        expected = [
            'POST',
            '/',
            '',
            'content-type:application/x-www-form-urlencoded',
            'host:iam.amazonaws.com',
            'x-amz-date:20110909T233600Z',
            '',
            'content-type;host;x-amz-date',
            'b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f95'
            '5085e2']
        expected = '\n'.join(expected)
        cano_req = AWS4Auth.get_canonical_request(req, cano_headers,
                                                  signed_headers)
        self.assertEqual(cano_req, expected)

    @unittest.skipIf(amz_aws4_testsuite is None, 'aws4_testsuite unavailable,'
                     ' download it from http://docs.aws.amazon.com/general/la'
                     'test/gr/samples/aws4_testsuite.zip')
    def test_amz_test_suite(self):
        for group_name in amz_aws4_testsuite.data:
            # use new 3.4 subtests if available
            if hasattr(self, 'subTest'):
                with self.subTest(group_name=group_name):
                    self._test_amz_test_suite_item(group_name)
            else:
                self._test_amz_test_suite_item(group_name)

    def _test_amz_test_suite_item(self, group_name):
        group = amz_aws4_testsuite.data[group_name]
        req = request_from_text(group['.req'])
        if 'content-length' in req.headers:
            del req.headers['content-length']
        include_hdrs = list(req.headers)
        AWS4Auth.encode_body(req)
        hsh = hashlib.sha256(req.body or b'')
        req.headers['x-amz-content-sha256'] = hsh.hexdigest()
        result = AWS4Auth.get_canonical_headers(req, include_hdrs)
        cano_headers, signed_headers = result
        cano_req = AWS4Auth.get_canonical_request(req, cano_headers,
                                                  signed_headers)
        msg = 'Group: ' + group_name
        self.assertEqual(cano_req, group['.creq'], msg=msg)


class AWS4Auth_RequestSign_Test(unittest.TestCase):

    def test_generate_signature(self):
        """
        Using example data from
        http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

        """
        access_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
        region = 'us-east-1'
        service = 'iam'
        date = '20110909'
        timestamp = '20110909T233600Z'
        key = AWS4SigningKey(access_key, region, service, date)
        req_text = [
            'POST https://iam.amazonaws.com/ HTTP/1.1',
            'Host: iam.amazonaws.com',
            'Content-Length: 54',
            'Content-Type: application/x-www-form-urlencoded; charset=utf-8',
            'X-Amz-Date: 20140611T003735Z',
            '',
            'Action=ListUsers&Version=2010-05-08']
        req_text = '\n'.join(req_text) + '\n'
        req = request_from_text(req_text)
        del req.headers['content-length']
        include_hdrs = list(req.headers)
        auth = AWS4Auth('dummy', key, include_hdrs=include_hdrs)
        AWS4Auth.encode_body(req)
        hsh = hashlib.sha256(req.body)
        req.headers['x-amz-content-sha256'] = hsh.hexdigest()
        sreq = auth(req, timestamp=timestamp)
        signature = sreq.headers['Authorization'].split('=')[3]
        expected = ('ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c541'
                   '74deb456c')
        self.assertEqual(signature, expected)

    @unittest.skipIf(amz_aws4_testsuite is None, 'aws4_testsuite unavailable,'
                     ' download it from http://docs.aws.amazon.com/general/la'
                     'test/gr/samples/aws4_testsuite.zip')
    def test_amz_test_suite(self):
        for group_name in sorted(amz_aws4_testsuite.data):
            # use new 3.4 subtests if available
            if hasattr(self, 'subTest'):
                with self.subTest(group_name=group_name):
                    self._test_amz_test_suite_item(group_name)
            else:
                self._test_amz_test_suite_item(group_name)

    def _test_amz_test_suite_item(self, group_name):
        group = amz_aws4_testsuite.data[group_name]
        req = request_from_text(group['.req'])
        if 'content-length' in req.headers:
            del req.headers['content-length']
        include_hdrs = list(req.headers)
        AWS4Auth.encode_body(req)
        hsh = hashlib.sha256(req.body or b'')
        req.headers['x-amz-content-sha256'] = hsh.hexdigest()
        key = AWS4SigningKey(amz_aws4_testsuite.access_key,
                             amz_aws4_testsuite.region,
                             amz_aws4_testsuite.service,
                             amz_aws4_testsuite.date)
        auth = AWS4Auth(amz_aws4_testsuite.access_id, key,
                        include_hdrs=include_hdrs)
        sreq = auth(req, timestamp=amz_aws4_testsuite.timestamp)
        auth_hdr = sreq.headers['Authorization']
        msg = 'Group: ' + group_name
        self.assertEqual(auth_hdr, group['.authz'], msg=msg)


if __name__ == '__main__':
    unittest.main(verbosity=2)
