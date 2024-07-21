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
import warnings
import datetime
from errno import ENOENT

try:
    from urllib.parse import quote, urlparse, urlunparse
except ImportError:
    from urllib import quote
    from urlparse import urlparse, urlunparse

import requests
import httpx

from requests_aws4auth import AWS4Auth
from requests_aws4auth.aws4signingkey import AWS4SigningKey
from requests_aws4auth.exceptions import DateFormatError, NoSecretKeyError
from six import PY2, u


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
    secret_key: The AWS secret access key used by the test examples in the
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
        self.secret_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
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
    match = re.search(r'^([a-z]+) (.*) (http/[0-9]\.[0-9])$', lines[0], re.I)
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
    body = '\n'.join(lines[idx + 1:])
    req = requests.Request(method, url, headers=headers, data=body)
    prep = req.prepare()
    # AWS4 testsuite includes query string test cases that are corrected by requests auto-quoting
    # undo auto-quoting of the query string by restoring original query and fragment
    orig_parts = urlparse(url)
    prep_parts = urlparse(prep.url)
    restored_url = urlunparse((prep_parts.scheme, prep_parts.netloc, prep_parts.path, prep_parts.params,
                               orig_parts.query, orig_parts.fragment))
    prep.url = restored_url
    return prep


class AWS4_SigningKey_Test(unittest.TestCase):

    def test_basic_instantiation(self):
        obj = AWS4SigningKey('secret_key', 'region', 'service', 'date')
        self.assertEqual(obj.region, 'region')
        self.assertEqual(obj.service, 'service')
        self.assertEqual(obj.scope, 'date/region/service/aws4_request')

    def test_store_secret_key(self):
        obj = AWS4SigningKey('secret_key', 'region', 'service',
                             store_secret_key=True)
        self.assertEqual(obj.secret_key, 'secret_key')

    def test_no_store_secret_key(self):
        obj = AWS4SigningKey('secret_key', 'region', 'service',
                             store_secret_key=False)
        self.assertEqual(obj.secret_key, None)

    def test_default_store_secret_key(self):
        obj = AWS4SigningKey('secret_key', 'region', 'service')
        self.assertEqual(obj.secret_key, 'secret_key')

    def test_date(self):
        test_date = datetime.datetime.utcnow().strftime('%Y%m%d')
        obj = AWS4SigningKey('secret_key', 'region', 'service')
        if obj.date != test_date:
            test_date = datetime.datetime.utcnow().strftime('%Y%m%d')
        self.assertEqual(obj.date, test_date)

    def test_amz_date(self):
        """
        Will be removed when deprecated amz_date attribute is removed

        """
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter('always')
            test_date = datetime.datetime.utcnow().strftime('%Y%m%d')
            obj = AWS4SigningKey('secret_key', 'region', 'service')
            if obj.amz_date != test_date:
                test_date = datetime.datetime.utcnow().strftime('%Y%m%d')
            self.assertEqual(obj.amz_date, test_date)

    def test_amz_date_warning(self):
        """
        Will be removed when deprecated amz_date attribute is removed

        """
        warnings.resetwarnings()
        with warnings.catch_warnings(record=True) as w:
            obj = AWS4SigningKey('secret_key', 'region', 'service')
            if PY2:
                warnings.simplefilter('always')
                obj.amz_date
                self.assertEqual(len(w), 1)
                self.assertEqual(w[-1].category, DeprecationWarning)
            else:
                warnings.simplefilter('ignore')
                self.assertWarns(DeprecationWarning, getattr, obj, 'amz_date')

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
        secret_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
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
        result = AWS4SigningKey.generate_key(secret_key, region,
                                             service, date, intermediates=True)
        for i, hsh in enumerate(result):
            hsh = [ord(x) for x in hsh] if PY2 else list(hsh)
            self.assertEqual(hsh, expected[i], msg='Item number {}'.format(i))

    def test_generate_key(self):
        """
        Using example data from:
        http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

        """
        secret_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
        region = 'us-east-1'
        service = 'iam'
        date = '20110909'
        expected = [152, 241, 216, 137, 254, 196, 244, 66, 26, 220, 82, 43,
                    171, 12, 225, 248, 46, 105, 41, 194, 98, 237, 21, 229,
                    169, 76, 144, 239, 209, 227, 176, 231]
        key = AWS4SigningKey.generate_key(secret_key, region, service, date)
        key = [ord(x) for x in key] if PY2 else list(key)
        self.assertEqual(key, expected)

    def test_instantiation_generate_key(self):
        """
        Using example data from:
        http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

        """
        secret_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
        region = 'us-east-1'
        service = 'iam'
        date = '20110909'
        expected = [152, 241, 216, 137, 254, 196, 244, 66, 26, 220, 82, 43,
                    171, 12, 225, 248, 46, 105, 41, 194, 98, 237, 21, 229,
                    169, 76, 144, 239, 209, 227, 176, 231]
        key = AWS4SigningKey(secret_key, region, service, date).key
        key = [ord(x) for x in key] if PY2 else list(key)
        self.assertEqual(key, expected)


class AWS4Auth_Instantiate_Test(unittest.TestCase):

    def test_instantiate_from_args(self):
        test_date = datetime.datetime.utcnow().strftime('%Y%m%d')
        test_inc_hdrs = set(['a', 'b', 'c'])
        auth = AWS4Auth('access_id',
                        'secret_key',
                        'region',
                        'service',
                        include_hdrs=test_inc_hdrs,
                        raise_invalid_date=True,
                        session_token='sessiontoken')
        self.assertEqual(auth.access_id, 'access_id')
        self.assertEqual(auth.region, 'region')
        self.assertEqual(auth.service, 'service')
        self.assertEqual(auth.include_hdrs, test_inc_hdrs)
        self.assertEqual(auth.raise_invalid_date, True)
        self.assertEqual(auth.session_token, 'sessiontoken')
        self.assertIsInstance(auth.signing_key, AWS4SigningKey)
        self.assertEqual(auth.signing_key.region, 'region')
        self.assertEqual(auth.signing_key.service, 'service')
        if test_date != auth.signing_key.date:
            test_date = datetime.datetime.utcnow().strftime('%Y%m%d')
        self.assertEqual(auth.signing_key.date, test_date)
        expected = '{}/region/service/aws4_request'.format(test_date)
        self.assertEqual(auth.signing_key.scope, expected)

    def test_instantiate_from_signing_key(self):
        key = AWS4SigningKey('secret_key', 'region', 'service', 'date')
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

    def test_raise_invalid_date_default(self):
        auth = AWS4Auth('access_id',
                        'secret_key',
                        'region',
                        'service')
        self.assertFalse(auth.raise_invalid_date)

    def test_default_include_hdrs(self):
        auth = AWS4Auth('access_id',
                        'secret_key',
                        'region',
                        'service')
        check_set = {'host', 'content-type', 'date', 'x-amz-*'}
        self.assertSetEqual(set(auth.include_hdrs), check_set)


class AWS4Auth_Date_Test(unittest.TestCase):
    def test_parse_rfc7231(self):
        tests = {
            'Sun, 05 Jan 1980 01:01:01 GMT': '1980-01-05',
            'Mon, 06 Feb 1985 01:01:01 GMT': '1985-02-06',
            'Tue, 07 Mar 1990 01:01:01 GMT': '1990-03-07',
            'Wed, 08 Apr 1999 01:01:01 GMT': '1999-04-08',
            'Thu, 09 May 2000 01:01:01 GMT': '2000-05-09',
            'Fri, 10 Jun 2100 01:01:01 GMT': '2100-06-10',
            'Sat, 02 Jul 1900 10:11:12 GMT': '1900-07-02',
            'Sun, 01 Aug 1970 00:00:00 GMT': '1970-08-01',
            'Mon, 09 Sep 2011 23:36:00 GMT': '2011-09-09',
            'Tue, 10 Oct 2000 01:01:01 GMT': '2000-10-10',
            'Wed, 22 Nov 2015 19:43:01 GMT': '2015-11-22',
            'Thu, 31 Dec 2130 00:00:00 GMT': '2130-12-31',
        }
        for src, check in tests.items():
            self.assertEqual(AWS4Auth.parse_date(src), check)

    def test_parse_rfc850(self):
        tests = {
            'Sunday, 05-Jan-80 01:01:01 GMT': '2080-01-05',
            'Monday, 06-Feb-85 01:01:01 EST': '2085-02-06',
            'Tuesday, 07-Mar-90 01:01:01 BST': '2090-03-07',
            'Wednesday, 08-Apr-99 01:01:01 GMT': '2099-04-08',
            'Thursday, 09-May-00 01:01:01 GMT': '2000-05-09',
            'Friday, 10-Jun-00 01:01:01 GMT': '2000-06-10',
            'Saturday, 02-Jul-00 10:11:12 GMT': '2000-07-02',
            'Sunday, 01-Aug-70 00:00:00 GMT': '2070-08-01',
            'Monday, 09-Sep-11 23:36:00 GMT': '2011-09-09',
            'Tuesday, 10-Oct-00 01:01:01 GMT': '2000-10-10',
            'Wednesday, 22-Nov-15 19:43:01 GMT': '2015-11-22',
            'Thursday, 31-Dec-30 00:00:00 GMT': '2030-12-31',
        }
        for src, check in tests.items():
            self.assertEqual(AWS4Auth.parse_date(src), check)

    def test_parse_ctime(self):
        tests = {
            'Sun Jan 5 01:01:01 1980': '1980-01-05',
            'Mon Feb 6 01:01:01 1985': '1985-02-06',
            'Tue Mar 7 01:01:01 1990': '1990-03-07',
            'Wed Apr 8 01:01:01 1999': '1999-04-08',
            'Thu May 9 01:01:01 2000': '2000-05-09',
            'Fri Jun 10 01:01:01 2100': '2100-06-10',
            'Sat Jul 2 10:11:12 1900': '1900-07-02',
            'Sun Aug 1 00:00:00 1970': '1970-08-01',
            'Mon Sep 9 23:36:00 2011': '2011-09-09',
            'Tue Oct 10 01:01:01 2000': '2000-10-10',
            'Wed Nov 22 19:43:01 2015': '2015-11-22',
            'Thu Dec 31 00:00:00 2130': '2130-12-31',
        }
        for src, check in tests.items():
            self.assertEqual(AWS4Auth.parse_date(src), check)

    def test_parse_amzdate(self):
        tests = {
            '19800105T010101Z': '1980-01-05',
            '19850206T010101Z': '1985-02-06',
            '19900307T010101Z': '1990-03-07',
            '19990408T010101Z': '1999-04-08',
            '20000509T010101Z': '2000-05-09',
            '21000610T010101Z': '2100-06-10',
            '19000702T101112Z': '1900-07-02',
            '19700801T000000Z': '1970-08-01',
            '20110909T233600Z': '2011-09-09',
            '20001010T010101Z': '2000-10-10',
            '20151122T194301Z': '2015-11-22',
            '21301231T000000Z': '2130-12-31',
        }
        for src, check in tests.items():
            self.assertEqual(AWS4Auth.parse_date(src), check)

    def test_parse_rfc3339(self):
        tests = {
            '1980-01-05': '1980-01-05',
            '1985-02-06T01:01:01+01:00': '1985-02-06',
            '1990-03-07t02:02:02-09:00': '1990-03-07',
            '1999-04-08T03:03:03-00:00': '1999-04-08',
            '2000-05-09t04:04:04Z': '2000-05-09',
            '2100-06-10T05:05:05Z': '2100-06-10',
            '1900-07-02T06:06:06Z': '1900-07-02',
            '1970-08-01T07:07:07Z': '1970-08-01',
            '2011-09-09T08:08:08Z': '2011-09-09',
            '2000-10-10T09:09:09Z': '2000-10-10',
            '2015-11-22T10:10:10Z': '2015-11-22',
            '2130-12-31T11:11:11Z': '2130-12-31',
        }
        for src, check in tests.items():
            self.assertEqual(AWS4Auth.parse_date(src), check)

    def test_parse_bad_date(self):
        for date_str in ['failfailfail', '', '111111111', '111-11-11']:
            self.assertRaises(DateFormatError, AWS4Auth.parse_date, date_str)

    def test_get_request_date__date_only(self):
        tests = {
            'Sun, 05 Jan 1980 01:01:01 GMT': (1980, 1, 5),
            '19000404T010101Z': (1900, 4, 4),
            'Monday, 06-Feb-85 01:01:01 EST': (2085, 2, 6),
            'Sun Jan 5 01:01:01 1980': (1980, 1, 5),
            '1985-02-06T01:01:01+01:00': (1985, 2, 6),
        }
        tests = dict([(k, datetime.date(*v)) for k, v in tests.items()])
        for date_str, check in tests.items():
            req = requests.Request('GET', 'http://blah.com')
            req = req.prepare()
            req.headers['date'] = date_str
            result = AWS4Auth.get_request_date(req)
            self.assertEqual(result, check, date_str)

    def test_get_request_date__xamzdate_only(self):
        date_str = '19000404T010101Z'
        check = datetime.date(1900, 4, 4)
        req = requests.Request('GET', 'http://blah.com')
        req = req.prepare()
        req.headers['x-amz-date'] = date_str
        result = AWS4Auth.get_request_date(req)
        self.assertEqual(result, check, date_str)

    def test_get_request_date__check_prefer_xamzdate(self):
        xamzdate_str = '19000404T010101Z'
        check = datetime.date(1900, 4, 4)
        date_str = 'Sun, 05 Jan 1980 01:01:01 GMT'
        req = requests.Request('GET', 'http://blah.com')
        req = req.prepare()
        req.headers['x-amz-date'] = xamzdate_str
        req.headers['date'] = date_str
        result = AWS4Auth.get_request_date(req)
        self.assertEqual(result, check)

    def test_get_request_date__date_and_invalid_xamzdate(self):
        xamzdate_str = '19000404X010101Z'
        date_str = 'Sun, 05 Jan 1980 01:01:01 GMT'
        check = datetime.date(1980, 1, 5)
        req = requests.Request('GET', 'http://blah.com')
        req = req.prepare()
        req.headers['x-amz-date'] = xamzdate_str
        req.headers['date'] = date_str
        result = AWS4Auth.get_request_date(req)
        self.assertEqual(result, check)

    def test_get_request_date__no_headers(self):
        req = requests.Request('GET', 'http://blah.com')
        req = req.prepare()
        check = None
        result = AWS4Auth.get_request_date(req)
        self.assertEqual(result, check)

    def test_get_request_date__invalid_xamzdate(self):
        req = requests.Request('GET', 'http://blah.com')
        req = req.prepare()
        req.headers['x-amz-date'] = ''
        check = None
        result = AWS4Auth.get_request_date(req)
        self.assertEqual(result, check)

    def test_get_request_date__invalid_date(self):
        check = None
        req = requests.Request('GET', 'http://blah.com')
        req = req.prepare()
        req.headers['date'] = ''
        result = AWS4Auth.get_request_date(req)
        self.assertEqual(result, check)

    def test_get_request_date__invalid_both(self):
        check = None
        req = requests.Request('GET', 'http://blah.com')
        req = req.prepare()
        req.headers['x-amz-date'] = ''
        req.headers['date'] = ''
        result = AWS4Auth.get_request_date(req)
        self.assertEqual(result, check)

    def test_aws4auth_add_header(self):
        req = requests.Request('GET', 'http://blah.com')
        req = req.prepare()
        if 'date' in req.headers: del req.headers['date']
        secret_key = 'dummy'
        region = 'us-east-1'
        service = 'iam'
        key = AWS4SigningKey(secret_key, region, service)
        auth = AWS4Auth('dummy', key)
        sreq = auth(req)
        self.assertIn('x-amz-date', sreq.headers)
        self.assertIsNotNone(AWS4Auth.get_request_date(sreq))


class AWS4Auth_Regenerate_Signing_Key_Test(unittest.TestCase):

    def setUp(self):
        self.region = 'region'
        self.service = 'service'
        self.date = '19990101'
        self.secret_key = 'secret_key'
        self.access_id = 'access_id'
        self.auth = AWS4Auth(self.access_id, self.secret_key, self.region,
                             self.service, self.date)
        self.sig_key_no_secret = AWS4SigningKey(self.secret_key,
                                                self.region,
                                                self.service,
                                                self.date,
                                                False)
        self.auth_no_secret = AWS4Auth(self.access_id, self.sig_key_no_secret)

    def test_regen_signing_key_no_secret_nosecretkey_raise(self):
        auth = self.auth_no_secret
        check_id = id(auth.signing_key)
        self.assertRaises(NoSecretKeyError, auth.regenerate_signing_key)
        self.assertEqual(id(auth.signing_key), check_id)

    def test_regen_signing_key_no_key_nosecretkey_raise(self):
        auth = self.auth
        auth.signing_key = None
        self.assertRaises(NoSecretKeyError, auth.regenerate_signing_key)
        self.assertIsNone(auth.signing_key)

    def test_regen_signing_key_new_key(self):
        auth = self.auth
        old_id = id(auth.signing_key)
        auth.regenerate_signing_key()
        self.assertNotEqual(old_id, id(auth.signing_key))

    def test_regen_signing_key_inherit_previous_scope(self):
        auth = self.auth
        auth.regenerate_signing_key()
        key = auth.signing_key
        self.assertEqual(key.region, self.region)
        self.assertEqual(key.service, self.service)
        self.assertEqual(key.date, self.date)
        self.assertEqual(key.secret_key, self.secret_key)
        self.assertEqual(auth.region, self.region)
        self.assertEqual(auth.service, self.service)
        self.assertEqual(auth.date, self.date)

    def test_regen_signing_key_use_override_args(self):
        auth = self.auth
        new_key = 'new_secret_key'
        new_region = 'new_region'
        new_service = 'new_service'
        new_date = 'new_date'
        auth.regenerate_signing_key(new_key, new_region, new_service,
                                    new_date)
        self.assertEqual(auth.signing_key.secret_key, new_key)
        self.assertEqual(auth.signing_key.region, new_region)
        self.assertEqual(auth.signing_key.service, new_service)
        self.assertEqual(auth.signing_key.date, new_date)

    def test_regen_signing_key_no_key_supplied_secret_key(self):
        auth = self.auth
        auth.signing_key = None
        auth.regenerate_signing_key(self.secret_key)
        self.assertEqual(auth.signing_key.secret_key, self.secret_key)
        self.assertEqual(auth.signing_key.region, self.region)
        self.assertEqual(auth.signing_key.service, self.service)
        self.assertEqual(auth.signing_key.date, self.date)
        self.assertTrue(auth.signing_key.store_secret_key)


class AWS4Auth_EncodeBody_Test(unittest.TestCase):

    def setUp(self):
        self.req = SimpleNamespace()
        self.req.body = ''
        self.req.headers = {}

    def test_encode_body_safe_unicode_to_utf8(self):
        self.req.body = 'hello'
        AWS4Auth.encode_body(self.req)
        self.assertEqual(self.req.body, b'\x68\x65\x6c\x6c\x6f')
        expected = 'text/plain; charset=utf-8'
        self.assertEqual(self.req.headers['content-type'], expected)

    def test_encode_body_unsafe_unicode_to_utf8(self):
        self.req.body = '☃'
        AWS4Auth.encode_body(self.req)
        self.assertEqual(self.req.body, b'\xe2\x98\x83')
        expected = 'text/plain; charset=utf-8'
        self.assertEqual(self.req.headers['content-type'], expected)

    def test_encode_body_safe_unicode_to_other_bytes(self):
        self.req.body = 'hello'
        self.req.headers['content-type'] = 'text/plain; charset=ascii'
        AWS4Auth.encode_body(self.req)
        self.assertEqual(self.req.body, b'\x68\x65\x6c\x6c\x6f')
        expected = 'text/plain; charset=ascii'
        self.assertEqual(self.req.headers['content-type'], expected)

    def test_encode_body_unsafe_unicode_to_other_bytes(self):
        self.req.body = '€'
        self.req.headers['content-type'] = 'text/plain; charset=cp1252'
        AWS4Auth.encode_body(self.req)
        self.assertEqual(self.req.body, b'\x80')
        expected = 'text/plain; charset=cp1252'
        self.assertEqual(self.req.headers['content-type'], expected)

    def test_encode_body_bytes(self):
        text = b'hello'
        self.req.body = text
        AWS4Auth.encode_body(self.req)
        self.assertEqual(self.req.body, text)
        self.assertEqual(self.req.headers, {})


class AWS4Auth_AmzCanonicalPath_Test(unittest.TestCase):

    def setUp(self):
        self.nons3auth = AWS4Auth('id', 'secret', 'us-east-1', 'es')
        self.s3auth = AWS4Auth('id', 'secret', 'us-east-1', 's3')

    def test_basic(self):
        path = '/'
        encoded = self.nons3auth.amz_cano_path(path)
        self.assertEqual(encoded, path)

    def test_handle_querystring(self):
        path = '/test/index.html?param1&param2=blah*'
        encoded = self.nons3auth.amz_cano_path(path)
        self.assertEqual(encoded, path)

    def test_handle_path_normalization(self):
        path = '/./test/../stuff//more/'
        expected = '/stuff/more/'
        encoded = self.nons3auth.amz_cano_path(path)
        self.assertEqual(encoded, expected)

    def test_handle_basic_quoting(self):
        path = '/test/hello-*.&^~+{}!$£_ '
        expected = '/test/hello-%2A.%26%5E~%2B%7B%7D%21%24%C2%A3_%20'
        encoded = self.nons3auth.amz_cano_path(path)
        self.assertEqual(encoded, expected)

    def test_handle_percent_encode_non_s3(self):
        """
        Test percent signs are themselves percent encoded for non-S3
        services.

        """
        path = '/test/%2a%2b%25/~-_^& %%'
        expected = '/test/%252a%252b%2525/~-_%5E%26%20%25%25'
        auth = AWS4Auth('id', 'secret', 'us-east-1', 'es')
        encoded = auth.amz_cano_path(path)
        self.assertEqual(encoded, expected)

    def test_handle_percent_encode_s3(self):
        """
        Test percents are handled correctly for S3. S3 expected the
        path to be unquoted once before being quoted.

        """
        path = '/test/%2a%2b%25/~-_^& %%'
        expected = '/test/%2A%2B%25/~-_%5E%26%20%25%25'
        auth = AWS4Auth('id', 'secret', 'us-east-1', 's3')
        encoded = auth.amz_cano_path(path)
        self.assertEqual(encoded, expected)


class AWS4Auth_AmzCanonicalQuerystring_Test(unittest.TestCase):

    def setUp(self):
        self.auth = AWS4Auth('id', 'secret', 'us-east-1', 'es')

    def test_basic(self):
        qs = 'greet=hello'
        encoded = self.auth.amz_cano_querystring(qs)
        self.assertEqual(encoded, qs)

    def test_multiple_params(self):
        qs = 'greet=hello&impression=wtf'
        encoded = self.auth.amz_cano_querystring(qs)
        self.assertEqual(encoded, qs)

    def test_space(self):
        """
        Test space in the querystring. See post-vanilla-query-space test in the
        downloadable amz testsuite for expected behaviour.

        """
        qs = 'greet=hello&impression =wtf'
        expected = 'greet=hello&impression='
        encoded = self.auth.amz_cano_querystring(qs)
        self.assertEqual(encoded, expected)

    def test_quoting(self):
        qs = 'greet=hello&impression=!#"£$%^*()-_@~{},.<>/\\'
        expected = 'greet=hello&impression=%21%23%22%C2%A3%24%25%5E%2A%28%29-_%40~%7B%7D%2C.%3C%3E%2F%5C'
        encoded = self.auth.amz_cano_querystring(qs)
        self.assertEqual(encoded, expected)

    def test_basic_ordering(self):
        ret = AWS4Auth.amz_cano_querystring('foo=1&bar=2')
        self.assertEqual(ret, 'bar=2&foo=1')

    def test_hyphen_key(self):
        '''a-foo should come after a. This requires key-sorting.
           https://github.com/tedder/requests-aws4auth/issues/21
        '''
        ret = AWS4Auth.amz_cano_querystring('foo=1&bar=2&foo_bar=1&foo-bar=1')
        self.assertEqual(ret, 'bar=2&foo=1&foo-bar=1&foo_bar=1')

    def test_multi_params(self):
        '''standard key-sorting doesn't ensure the values are in order.
           https://github.com/tedder/requests-aws4auth/issues/49
        '''
        ret = AWS4Auth.amz_cano_querystring('foo=1&bar=2&bar=3&bar=1')
        self.assertEqual(ret, 'bar=1&bar=2&bar=3&foo=1')

    def test_encoded_ampersand(self):
        q = quote('a&b', safe='')
        ret = AWS4Auth.amz_cano_querystring('foo=%s&bar=1' % q)
        self.assertEqual(ret, 'bar=1&foo=%s' % q)

    def test_encoded_equal(self):
        q = quote('a=b', safe='')
        ret = AWS4Auth.amz_cano_querystring('foo=%s&bar=1' % q)
        self.assertEqual(ret, 'bar=1&foo=%s' % q)

    def test_encoded_plus(self):
        q = quote('a+b', safe='')
        ret = AWS4Auth.amz_cano_querystring('foo=%s&bar=1' % q)
        self.assertEqual(ret, 'bar=1&foo=%s' % q)

    def test_encoded_space(self):
        q = quote('a b', safe='')
        ret = AWS4Auth.amz_cano_querystring('foo=%s&bar=1' % q)
        self.assertEqual(ret, 'bar=1&foo=%s' % q)

    def test_encoded_path(self):
        q = quote('/?a=b&c=d', safe='')
        ret = AWS4Auth.amz_cano_querystring('foo=%s&bar=1' % q)
        self.assertEqual(ret, 'bar=1&foo=%s' % q)


class AWS4Auth_GetCanonicalHeaders_Test(unittest.TestCase):

    def test_invalid_header(self):
        """These should fail."""
        headers = [
            'My-Header1: a',
            'My-Header2: "a   b   c"',
            "My-Header3:\nab"
        ]

        for h_to_test in headers:
            h_dict = dict([item.split(':') for item in [h_to_test]])
            req = requests.Request('GET',
                                   'http://iam.amazonaws.com',
                                   headers=h_dict)
            with self.assertRaises(requests.exceptions.InvalidHeader):
                rp = req.prepare()

    def test_invalid_header_using_httpx(self):
        headers = [
            'My-Header1: a',
            'My-Header2: "a   b   c"',
            "My-Header3:\nab"
        ]

        for h_to_test in headers:
            h_dict = dict([item.split(':') for item in [h_to_test]])
            req = httpx.Request('GET',
                                'http://iam.amazonaws.com',
                                headers=h_dict)
            req._prepare({})

    def test_headers_amz_example(self):
        """
        Using example from:
        http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

        """
        hdr_text = [
            'host:iam.amazonaws.com',
            'Content-type:application/x-www-form-urlencoded; charset=utf-8',
            'My-header1:a   b   c ',
            'x-amz-date:20120228T030031Z',
            'My-Header2:"a   b   c"']
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

    def test_headers_amz_example_using_httpx(self):
        """
        Using example from:
        http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

        """
        hdr_text = [
            'host:iam.amazonaws.com',
            'Content-type:application/x-www-form-urlencoded; charset=utf-8',
            'My-header1:a   b   c ',
            'x-amz-date:20120228T030031Z',
            'My-Header2:"a   b   c"']
        headers = dict([item.split(':') for item in hdr_text])
        req = httpx.Request('GET',
                               'http://iam.amazonaws.com',
                               headers=headers)
        req._prepare({})
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

    def test_netloc_port_is_stripped_for_standard_port(self):
        """
        Test that change in d190dcb doesn't regress: The Host header is not
        part of the prepared request, but generated later, and the port is
        stripped from that header if it is the standard HTTPS port.  This
        verifies that if the URL explicitly contains the port the library still
        generates a signature with the correct Host header.

        """
        req = requests.Request('GET', 'https://amazonaws.com:443')
        preq = req.prepare()
        self.assertNotIn('host', preq.headers)
        result = AWS4Auth.get_canonical_headers(preq, include=['host'])
        cano_hdrs, signed_hdrs = result
        expected = 'host:amazonaws.com\n'
        self.assertEqual(cano_hdrs, expected)

    def test_netloc_port_is_kept_for_non_standard_port(self):
        """
        The Host header is not part of the prepared request, but generated
        later, and the port is kept in the header if it is not the standard
        HTTPS port. d190dcb has a bug that also strips non-standard ports from
        the signature, causing signature and host header to mismatch. This is a
        regression test for that bug.

        """
        req = requests.Request('GET', 'https://amazonaws.com:8443')
        preq = req.prepare()
        self.assertNotIn('host', preq.headers)
        result = AWS4Auth.get_canonical_headers(preq, include=['host'])
        cano_hdrs, signed_hdrs = result
        expected = 'host:amazonaws.com:8443\n'
        self.assertNotEqual(cano_hdrs, expected)

    def test_netloc_port_is_stripped_for_standard_port_using_httpx(self):
        """
        Test that change in d190dcb doesn't regress: The Host header is part of
        the prepared request with httpx, and the port is stripped from that
        header if it is the standard HTTPS port. This verifies that if the URL
        explicitly contains the port the library generates a signature
        with the correct Host header.

        """
        req = httpx.Request('GET', 'https://amazonaws.com:443')
        req._prepare({})
        self.assertIn('host', req.headers)
        result = AWS4Auth.get_canonical_headers(req, include=['host'])
        cano_hdrs, signed_hdrs = result
        expected = 'host:amazonaws.com\n'
        self.assertEqual(cano_hdrs, expected)

    def test_netloc_port_is_kept_for_non_standard_port_using_httpx(self):
        """
        Test that change in d190dcb doesn't regress: The Host header is part of
        the prepared request with httpx, and the port is kept in the header if
        it is not the standard HTTPS port. This verifies that if the URL
        explicitly contains the port the library generates a signature with the
        correct Host header.

        """
        req = httpx.Request('GET', 'https://amazonaws.com:8443')
        req._prepare({})
        self.assertIn('host', req.headers)
        result = AWS4Auth.get_canonical_headers(req, include=['host'])
        cano_hdrs, signed_hdrs = result
        expected = 'host:amazonaws.com:8443\n'
        self.assertEqual(cano_hdrs, expected)


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
        auth = AWS4Auth('dummy', 'dummy', 'dummy', 'host')
        cano_req = auth.get_canonical_request(req, cano_headers,
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
        auth = AWS4Auth('dummy', 'dummy', 'dummy', 'host')
        cano_req = auth.get_canonical_request(req, cano_headers,
                                              signed_headers)
        msg = 'Group: ' + group_name
        self.assertEqual(cano_req, group['.creq'], msg=msg)


class AWS4Auth_RequestSign_Test(unittest.TestCase):

    def test_generate_signature(self):
        """
        Using example data from
        http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

        """
        secret_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
        region = 'us-east-1'
        service = 'iam'
        date = '20110909'
        key = AWS4SigningKey(secret_key, region, service, date)
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

    def test_generate_empty_body_signature(self):
        """
        Check that change in af03ce5 doesn't regress - ensure request body is
        not altered by signing process if it is empty (i.e None).

        """
        auth = AWS4Auth('x', 'x', 'us-east-1', 's3')
        req = requests.Request('GET', 'http://amazonaws.com', data=None)
        preq = req.prepare()
        sreq = auth(preq)
        self.assertEqual(sreq.body, None)

    def test_regen_key_on_date_mismatch(self):
        vals = [('20001231T235959Z', '20010101'),
                ('20000101T010101Z', '20000102'),
                ('19900101T010101Z', '20000101')]
        for amzdate, scope_date in vals:
            req = requests.Request('GET', 'http://blah.com')
            req = req.prepare()
            if 'date' in req.headers: del req.headers['date']
            req.headers['x-amz-date'] = amzdate
            secret_key = 'dummy'
            region = 'us-east-1'
            service = 'iam'
            date = scope_date
            key = AWS4SigningKey(secret_key, region, service, date)
            orig_id = id(key)
            auth = AWS4Auth('dummy', key)
            sreq = auth(req)
            self.assertNotEqual(id(auth.signing_key), orig_id)
            self.assertEqual(auth.date, amzdate.split('T')[0])

    def test_date_mismatch_nosecretkey_raise(self):
        key = AWS4SigningKey('secret_key', 'region', 'service', '1999010', False)
        auth = AWS4Auth('access_id', key)
        req = requests.Request('GET', 'http://blah.com')
        req = req.prepare()
        if 'date' in req.headers: del req.headers['date']
        req.headers['x-amz-date'] = '20000101T010101Z'
        self.assertRaises(NoSecretKeyError, auth, req)

    def test_sts_creds_include_security_token_header(self):
        key = AWS4SigningKey('secret_key', 'region', 'service', '1999010')
        auth = AWS4Auth('access_id', key, session_token='sessiontoken')
        req = requests.Request('GET', 'http://blah.com')
        req = req.prepare()
        sreq = auth(req)
        self.assertIn('x-amz-security-token', sreq.headers)
        self.assertEqual(sreq.headers.get('x-amz-security-token'), 'sessiontoken')

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
        key = AWS4SigningKey(amz_aws4_testsuite.secret_key,
                             amz_aws4_testsuite.region,
                             amz_aws4_testsuite.service,
                             amz_aws4_testsuite.date)
        auth = AWS4Auth(amz_aws4_testsuite.access_id, key,
                        include_hdrs=include_hdrs)
        sreq = auth(req)
        auth_hdr = sreq.headers['Authorization']
        msg = 'Group: ' + group_name
        self.assertEqual(auth_hdr, group['.authz'], msg=msg)




if __name__ == '__main__':
    #     unittest.main(verbosity=2, defaultTest='AWS4Auth_Instantiate_Test')
    #     unittest.main(verbosity=2, defaultTest='AWS4Auth_RequestSign_Test')
    unittest.main(verbosity=2)
