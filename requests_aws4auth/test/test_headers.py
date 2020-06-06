#!/usr/bin/env python
# coding: utf-8

import unittest
from requests_aws4auth import AWS4Auth


def ss(l):
  '''return a sorted set of a sortable thing'''
  return set(sorted(l))

class AWS4Auth_Header_Test(unittest.TestCase):
  _default_headers_sorted_set = ss(['content-type', 'date', 'host', 'x-amz-*'])


  def test_expected_default_headers(self):
    self.assertIsInstance(AWS4Auth.default_include_headers, set)
    self.assertSetEqual(ss(AWS4Auth.default_include_headers), self._default_headers_sorted_set)

  def test_base_instantiation(self):
    auth = AWS4Auth('access', 'secret', 'us-east-1', 'es')
    self.assertIsNone(auth.session_token)
    self.assertEqual(auth.default_include_headers, self._default_headers_sorted_set)
    self.assertEqual(auth.include_hdrs, self._default_headers_sorted_set)

  def test_override_default_headers_to_empty(self):
    # ignores the value because '7' isn't an iterable.
    auth = AWS4Auth('access', 'secret', 'us-east-1', 'es', include_hdrs=7)
    self.assertEqual(auth.include_hdrs, self._default_headers_sorted_set)

    # ignores the value because 'None' isn't an iterable.
    auth = AWS4Auth('access', 'secret', 'us-east-1', 'es', include_hdrs=None)
    self.assertEqual(auth.include_hdrs, self._default_headers_sorted_set)

    # uses the value because [] is iterable
    auth = AWS4Auth('access', 'secret', 'us-east-1', 'es', include_hdrs=[])
    self.assertEqual(len(auth.include_hdrs), 0)

    # uses the value because set() is iterable
    auth = AWS4Auth('access', 'secret', 'us-east-1', 'es', include_hdrs=set())
    self.assertEqual(len(auth.include_hdrs), 0)

  def test_override_default_headers_to_weird(self):
    # this is iterable.
    auth = AWS4Auth('access', 'secret', 'us-east-1', 'es', include_hdrs='aabb')
    self.assertEqual(auth.include_hdrs, ss(['a', 'b']))


  def test_override_default_headers_to_set(self):
    # These all evaluate to the same thing.
    # note no need to sort a set, they are unsortable:
    _expected_set = {'hello', 'world', 'foo'}

    # tuple to set
    auth = AWS4Auth('access', 'secret', 'us-east-1', 'es', include_hdrs=('hello', 'world', 'hello', 'foo'))
    self.assertSetEqual(auth.include_hdrs, _expected_set)

    # list to set
    auth = AWS4Auth('access', 'secret', 'us-east-1', 'es', include_hdrs=['hello', 'world', 'hello', 'foo'])
    self.assertSetEqual(auth.include_hdrs, _expected_set)

    # set with duplicates to set
    auth = AWS4Auth('access', 'secret', 'us-east-1', 'es', include_hdrs={'hello', 'world', 'hello', 'foo'})
    self.assertSetEqual(auth.include_hdrs, _expected_set)

    # 'set' syntax to set
    auth = AWS4Auth('access', 'secret', 'us-east-1', 'es', include_hdrs=set(['hello', 'world', 'hello', 'foo']))
    self.assertSetEqual(auth.include_hdrs, _expected_set)

    # no-dupes set to set
    auth = AWS4Auth('access', 'secret', 'us-east-1', 'es', include_hdrs={'hello', 'foo', 'world'})
    self.assertSetEqual(auth.include_hdrs, _expected_set)

    # no-dupes set to set, prove order is independent
    auth = AWS4Auth('access', 'secret', 'us-east-1', 'es', include_hdrs={'foo', 'hello', 'world'})
    self.assertSetEqual(auth.include_hdrs, _expected_set)


  def test_ensure_no_duplicate_headers(self):
    auth = AWS4Auth('access', 'secret', 'us-east-1', 'es')
    self.assertIsNone(auth.session_token)
    self.assertEqual(auth.default_include_headers, self._default_headers_sorted_set)
    self.assertEqual(auth.include_hdrs, self._default_headers_sorted_set)

