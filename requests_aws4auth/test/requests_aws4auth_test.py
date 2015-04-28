#!/usr/bin/env python
# coding: utf-8

"""
Tests for requests-aws4auth package.

aws_testsuite.zip
-----------------
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

Live service tests
------------------
This module contains tests against live AWS services. In order to run these
your AWS access ID and access key need to be specified in the AWS_ACCESS_ID
and AWS_ACCESS_ID environment variables respectively. This can be done with
something like:

$ AWS_ACCESS_ID='ID' AWS_ACCESS_KEY='KEY' python requests_aws4auth_test.py

If these variables are not provided the rest of the tests will still run but
the live service tests will be skipped.

The live tests perform information retrieval operations only, no chargeable
operations are performed!

"""

# Licensed under the MIT License:
# http://opensource.org/licenses/MIT


from __future__ import unicode_literals, print_function

import sys
import os
import unittest
import re
import hashlib
import itertools
import json
from datetime import datetime
from errno import ENOENT

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

import requests

sys.path = ['../../'] + sys.path
from requests_aws4auth import AWS4Auth
from requests_aws4auth.aws4signingkey import AWS4SigningKey
from requests_aws4auth.six import PY2, u


live_access_id = os.getenv('AWS_ACCESS_ID')
live_access_key = os.getenv('AWS_ACCESS_KEY')


class SimpleNamespace:
    pass


class AmzAws4TestSuite:
    """
    Load and wrap files from the aws4_testsuite.zip test suite from Amazon.

    Test suite files are available from:
    http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html

    Methods:
    load_testsuite_data: Staticmethod. Loads the test suite files found at the
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
        errmsg = ('Test Suite directory not found. Download the test suite'
                  'from here: http://docs.aws.amazon.com/general/latest/gr/'
                  'samples/aws4_testsuite.zip')
        if not os.path.exists(path):
            raise IOError(ENOENT, errmsg)
        files = sorted(os.listdir(path))
        if not files:
            raise IOError(ENOENT, errmsg)
        grouped = itertools.groupby(files, lambda x: os.path.splitext(x)[0])
        data = {}
        for group_name, items in grouped:
            if group_name == 'get-header-value-multiline':
                # skipping this test as it is incomplete as supplied in the
                # test suite
                continue
            group = {}
            for item in items:
                filepath = os.path.join(path, item)
                file_ext = os.path.splitext(item)[1]
                if PY2:
                    with open(filepath, 'U') as f:
                        content = unicode(f.read(), encoding='utf-8')
                else:
                    with open(filepath, encoding='utf-8') as f:
                        content = f.read()
                group[file_ext] = content
            data[group_name] = group
        return data
try:
    amz_aws4_testsuite = AmzAws4TestSuite()
except IOError as e:
    if e.errno == ENOENT:
        amz_aws4_testsuite = None
    else:
        raise e


def request_from_text(text):
    """
    Construct a Requests PreparedRequest using values provided in text.

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
        vals = headers.setdefault(hdr, [])
        vals.append(val)
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

    def test_date(self):
        test_date = datetime.utcnow().strftime('%Y%m%d')
        obj = AWS4SigningKey('access_key', 'region', 'service')
        if obj.amz_date != test_date:
            test_date = datetime.utcnow().strftime('%Y%m%d')
        self.assertEqual(obj.amz_date, test_date)

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
        test_date = datetime.utcnow().strftime('%Y%m%d')
        auth = AWS4Auth('access_id', 'access_key', 'region', 'service')
        self.assertEqual(auth.access_id, 'access_id')
        self.assertEqual(auth.region, 'region')
        self.assertEqual(auth.service, 'service')
        self.assertIsInstance(auth.signing_key, AWS4SigningKey)
        self.assertEqual(auth.signing_key.region, 'region')
        self.assertEqual(auth.signing_key.service, 'service')
        if test_date != auth.signing_key.amz_date:
            test_date = datetime.utcnow().strftime('%Y%m%d')
        self.assertEqual(auth.signing_key.amz_date, test_date)
        expected = '{}/region/service/aws4_request'.format(test_date)
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
        self.req.body = u('hello')
        AWS4Auth.encode_body(self.req)
        self.assertEqual(self.req.body, b'\x68\x65\x6c\x6c\x6f')
        expected = 'text/plain; charset=utf-8'
        self.assertEqual(self.req.headers['content-type'], expected)

    def test_encode_body_utf8_string_to_bytes(self):
        self.req.body = u('☃')
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

    def test_duplicate_headers(self):
        """
        Tests case of duplicate headers with different cased names. Uses a
        mock Request object with regular dict to hold headers, since Requests
        PreparedRequest dict is case-insensitive.

        """
        req = SimpleNamespace()
        req.headers = {'ZOO': 'zoobar',
                       'FOO': 'zoobar',
                       'zoo': 'foobar',
                       'Content-Type': 'text/plain',
                       'host': 'dummy'}
        include = [x for x in req.headers if x != 'Content-Type']
        result = AWS4Auth.get_canonical_headers(req, include=include)
        cano_headers, signed_headers = result
        cano_expected = 'foo:zoobar\nhost:dummy\nzoo:foobar,zoobar\n'
        signed_expected = 'foo;host;zoo'
        self.assertEqual(cano_headers, cano_expected)
        self.assertEqual(signed_headers, signed_expected)


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
        for group_name in sorted(amz_aws4_testsuite.data):
            group = amz_aws4_testsuite.data[group_name]
            # use new 3.4 subtests if available
            if hasattr(self, 'subTest'):
                with self.subTest(group_name=group_name, group=group):
                    self._test_amz_test_suite_item(group_name, group)
            else:
                self._test_amz_test_suite_item(group_name, group)

    def _test_amz_test_suite_item(self, group_name, group):
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
        key = AWS4SigningKey(access_key, region, service, date)
        req_text = [
            'POST https://iam.amazonaws.com/ HTTP/1.1',
            'Host: iam.amazonaws.com',
            'Content-Type: application/x-www-form-urlencoded; charset=utf-8',
            'X-Amz-Date: 20110909T233600Z',
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
        sreq = auth(req)
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
        req.headers['x-amz-date'] = amz_aws4_testsuite.timestamp
        key = AWS4SigningKey(amz_aws4_testsuite.access_key,
                             amz_aws4_testsuite.region,
                             amz_aws4_testsuite.service,
                             amz_aws4_testsuite.date)
        auth = AWS4Auth(amz_aws4_testsuite.access_id, key,
                        include_hdrs=include_hdrs)
        sreq = auth(req)
        auth_hdr = sreq.headers['Authorization']
        msg = 'Group: ' + group_name
        self.assertEqual(auth_hdr, group['.authz'], msg=msg)


@unittest.skipIf(live_access_id is None or live_access_key is None,
                 'AWS_ACCESS_ID and AWS_ACCESS_KEY environment variables not'
                 ' set, skipping live service tests')
class AWS4Auth_LiveService_Test(unittest.TestCase):
    """
    Tests against live AWS services. To run these you need to provide your
    AWS access ID and access key in the AWS_ACCESS_ID and AWS_ACCESS_KEY
    environment variables respectively.

    The AWS Support API is currently untested as it requires a premium
    subscription, though connection parameters are supplied below if you wish
    to try it.

    The following services do not work with AWS auth version 4 and are excluded
    from the tests:
        * Simple Email Service (SES)' - AWS auth v3 only
        * Simple Workflow Service - AWS auth v3 only
        * Import/Export - AWS auth v2 only
        * SimpleDB - AWS auth V2 only
        * DevPay - AWS auth v1 only
        * Mechanical Turk - has own signing mechanism

    """
    services = {
        'AppStream': 'appstream.us-east-1.amazonaws.com/applications',
        'Auto-Scaling': 'autoscaling.us-east-1.amazonaws.com/?Action=DescribeAutoScalingInstances&Version=2011-01-01',
        'CloudFormation': 'cloudformation.us-east-1.amazonaws.com?Action=ListStacks',
        'CloudFront': 'cloudfront.amazonaws.com/2014-11-06/distribution?MaxItems=1',
        'CloudHSM': {
            'method': 'POST',
            'req': 'cloudhsm.us-east-1.amazonaws.com',
            'headers': {'X-Amz-Target':
                        'CloudHsmFrontendService.ListAvailableZones',
                        'Content-Type': 'application/x-amz-json-1.1'},
            'body': '{}'},
        'CloudSearch': 'cloudsearch.us-east-1.amazonaws.com?Action=ListDomainNames&Version=2013-01-01',
        'CloudTrail': 'cloudtrail.us-east-1.amazonaws.com?Action=DescribeTrails',
        'CloudWatch (monitoring)': 'monitoring.us-east-1.amazonaws.com?Action=ListMetrics',
        'CloudWatch (logs)': {
            'method': 'POST',
            'req': 'logs.us-east-1.amazonaws.com',
            'headers': {'X-Amz-Target': 'Logs_20140328.DescribeLogGroups',
                        'Content-Type': 'application/x-amz-json-1.1'},
            'body': '{}'},
        'CodeDeploy': {
            'method': 'POST',
            'req': 'codedeploy.us-east-1.amazonaws.com',
            'headers': {'X-Amz-Target': 'CodeDeploy_20141006.ListApplications',
                        'Content-Type': 'application/x-amz-json-1.1'},
            'body': '{}'},
        'Cognito Identity': {
            'method': 'POST',
            'req': 'cognito-identity.us-east-1.amazonaws.com',
            'headers': {'Content-Type': 'application/json',
                        'X-Amz_Target': 'AWSCognitoIdentityService.ListIdentityPools'},
            'body': json.dumps({
                        'Operation': 'com.amazonaws.cognito.identity.model#ListIdentityPools',
                        'Service': 'com.amazonaws.cognito.identity.model#AWSCognitoIdentityService',
                        'Input': {'MaxResults': 1}})},
        'Cognito Sync': {
            'method': 'POST',
            'req': 'cognito-sync.us-east-1.amazonaws.com',
            'headers': {'Content-Type': 'application/json',
                        'X-Amz_Target': 'AWSCognitoSyncService.ListIdentityPoolUsage'},
            'body': json.dumps({
                        'Operation': 'com.amazonaws.cognito.sync.model#ListIdentityPoolUsage',
                        'Service': 'com.amazonaws.cognito.sync.model#AWSCognitoSyncService',
                        'Input': {'MaxResults': '1'}})},
        'Config': {
            'method': 'POST',
            'req': 'config.us-east-1.amazonaws.com',
            'headers': {'X-Amz-Target':
                        'StarlingDoveService.DescribeDeliveryChannels',
                        'Content-Type': 'application/x-amz-json-1.1'},
            'body': '{}'},
        'DataPipeline': {
            'req': 'datapipeline.us-east-1.amazonaws.com?Action=ListPipelines',
            'headers': {'X-Amz-Target': 'DataPipeline.ListPipelines'},
            'body': '{}'},
        'Direct Connect': {
            'method': 'POST',
            'req': 'directconnect.us-east-1.amazonaws.com',
            'headers': {'X-Amz-Target': 'OvertureService.DescribeConnections',
                        'Content-Type': 'application/x-amz-json-1.1'},
            'body': '{}'},
        'DynamoDB': {
            'method': 'POST',
            'req': 'dynamodb.us-east-1.amazonaws.com',
            'headers': {'X-Amz-Target': 'DynamoDB_20111205.ListTables',
                        'Content-Type': 'application/x-amz-json-1.0'},
            'body': '{}'},
        'Elastic Beanstalk': 'elasticbeanstalk.us-east-1.amazonaws.com/?Action=ListAvailableSolutionStacks&Version=2010-12-01',
        'ElastiCache': 'elasticache.us-east-1.amazonaws.com/?Action=DescribeCacheClusters&Version=2014-07-15',
        'EC2': 'ec2.us-east-1.amazonaws.com/?Action=DescribeRegions&Version=2014-06-15',
        'EC2 Container Service': 'ecs.us-east-1.amazonaws.com/?Action=ListClusters&Version=2014-11-13',
        'Elastic Load Balancing': 'elasticloadbalancing.us-east-1.amazonaws.com/?Action=DescribeLoadBalancers&Version=2012-06-01',
        'Elastic MapReduce': 'elasticmapreduce.us-east-1.amazonaws.com/?Action=DescribeJobFlows&Version=2009-03-31',
        'Elastic Transcoder': 'elastictranscoder.us-east-1.amazonaws.com/2012-09-25/pipelines',
        'Glacier': {
            'req': 'glacier.us-east-1.amazonaws.com/-/vaults',
            'headers': {'X-Amz-Glacier-Version': '2012-06-01'}},
        'Identity and Access Management (IAM)': 'iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08',
        'Key Management Service': {
            'method': 'POST',
            'req': 'kms.us-east-1.amazonaws.com',
            'headers': {'Content-Type': 'application/x-amz-json-1.1',
                        'X-Amz-Target': 'TrentService.ListKeys'},
            'body': '{}'},
        'Kinesis': {
            'method': 'POST',
            'req': 'kinesis.us-east-1.amazonaws.com',
            'headers': {'Content-Type': 'application/x-amz-json-1.1',
                        'X-Amz-Target': 'Kinesis_20131202.ListStreams'},
            'body': '{}'},
        'Lambda': 'lambda.us-east-1.amazonaws.com/2014-11-13/functions/',
        'Opsworks': {
            'method': 'POST',
            'req': 'opsworks.us-east-1.amazonaws.com',
            'headers': {'Content-Type': 'application/x-amz-json-1.1',
                        'X-Amz-Target': 'OpsWorks_20130218.DescribeStacks'},
            'body': '{}'},
        'Redshift': 'redshift.us-east-1.amazonaws.com/?Action=DescribeClusters&Version=2012-12-01',
        'Relational Database Service (RDS)': 'rds.us-east-1.amazonaws.com/?Action=DescribeDBInstances&Version=2012-09-17',
        'Route 53': 'route53.amazonaws.com/2013-04-01/hostedzone',
        'Simple Storage Service (S3)': 's3.amazonaws.com',
        'Simple Notification Service (SNS)': 'sns.us-east-1.amazonaws.com/?Action=ListTopics&Version=2010-03-31',
        'Simple Queue Service (SQS)': 'sqs.us-east-1.amazonaws.com/?Action=ListQueues',
        'Storage Gateway': {
            'method': 'POST',
            'req': 'storagegateway.us-east-1.amazonaws.com',
            'headers': {'Content-Type': 'application/x-amz-json-1.1',
                        'X-Amz-Target': 'StorageGateway_20120630.ListGateways'},
            'body': '{}'},
        'Security Token Service': 'sts.amazonaws.com/?Action=GetSessionToken&Version=2011-06-15',
        # 'Support': {
        #     'method': 'POST',
        #     'req': 'support.us-east-1.amazonaws.com',
        #     'headers': {'Content-Type': 'application/x-amz-json-1.0',
        #                 'X-Amz-Target': 'Support_20130415.DescribeServices'},
        #     'body': '{}'},
    }

    def test_live_services(self):
        for service_name in sorted(self.services):
            params = self.services[service_name]
            # use new 3.4 subtests if available
            if hasattr(self, 'subTest'):
                with self.subTest(service_name=service_name, params=params):
                    self._test_live_service(service_name, params)
            else:
                self._test_live_service(service_name, params)

    def _test_live_service(self, service_name, params):
        if isinstance(params, dict):
            method = params.get('method', 'GET')
            path_qs = params['req']
            headers = params.get('headers', {})
            body = params.get('body', '')
        else:
            method = 'GET'
            path_qs = params
            headers = {}
            body = ''
        service = path_qs.split('.')[0]
        url = 'https://' + path_qs
        region = 'us-east-1'
        auth = AWS4Auth(live_access_id, live_access_key, region, service)
        response = requests.request(method, url, auth=auth,
                                    data=body, headers=headers)
        # suppress socket close warnings
        response.connection.close()
        self.assertTrue(response.ok)

    def test_mobileanalytics(self):
        url = 'https://mobileanalytics.us-east-1.amazonaws.com/2014-06-05/events'
        service = 'mobileanalytics'
        region = 'us-east-1'
        dt = datetime.utcnow()
        date = dt.strftime('%Y%m%d')
        sig_key = AWS4SigningKey(live_access_key, region, service, date)
        auth = AWS4Auth(live_access_id, sig_key)
        headers = {'Content-Type': 'application/json',
                   'X-Amz-Date': dt.strftime('%Y%m%dT%H%M%SZ'),
                   'X-Amz-Client-Context':
                       json.dumps({
                           'client': {'client_id': 'a', 'app_title': 'a'},
                           'custom': {},
                           'env': {'platform': 'a'},
                           'services': {} })}
        body = json.dumps({
                    'events': [{
                        'eventType': 'a',
                        'timestamp': dt.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                        'session': {} }]})
        response = requests.post(url, auth=auth, headers=headers, data=body)
        response.connection.close()
        self.assertTrue(response.ok)


if __name__ == '__main__':
    unittest.main()
