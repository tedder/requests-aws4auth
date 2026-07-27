#!/usr/bin/env python

"""
Integration tests against a real SigV4 implementation on a non-standard port.

The host header bug tracked in #34/#65/#79 cannot be reproduced against AWS
itself: every AWS endpoint listens on 443, so the non-default-port path is
unreachable there. It is reproducible in seconds against any S3-compatible
server bound to another port, which is how it reaches users -- RadosGW on 7480,
MinIO on 9000, an SSH tunnel on 9200.

These tests need an endpoint to talk to. Point AWS4_TEST_S3_ENDPOINT at one and
they run; leave it unset and they skip.

MinIO:

    docker run -d --rm -p 9111:9000 \
      -e MINIO_ROOT_USER=AKIAIOSFODNN7EXAMPLE \
      -e MINIO_ROOT_PASSWORD=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
      minio/minio server /data
    AWS4_TEST_S3_ENDPOINT=http://127.0.0.1:9111 python -m unittest \
      requests_aws4auth.test.test_integration

RadosGW (Ceph), the server from #79:

    docker run -d --rm -p 7480:8080 \
      -e CEPH_DAEMON=demo -e RGW_NAME=localhost -e MON_IP=127.0.0.1 \
      -e CEPH_PUBLIC_NETWORK=0.0.0.0/0 -e CEPH_DEMO_UID=demo \
      -e CEPH_DEMO_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE \
      -e CEPH_DEMO_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
      quay.io/ceph/demo:latest-reef

The tests assert only that the server does not reject us with
SignatureDoesNotMatch. Any other outcome, including an authorization failure, is
treated as a pass: those depend on the server's bucket policy, whereas
SignatureDoesNotMatch means specifically that what we signed did not match what
we sent.

"""

# Licensed under the MIT License:
# http://opensource.org/licenses/MIT

import os
import unittest

import httpx
import requests

from requests_aws4auth import AWS4Auth


endpoint = os.getenv('AWS4_TEST_S3_ENDPOINT')
access_id = os.getenv('AWS4_TEST_S3_ACCESS_KEY', 'AKIAIOSFODNN7EXAMPLE')
secret_key = os.getenv('AWS4_TEST_S3_SECRET_KEY',
                       'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
region = os.getenv('AWS4_TEST_S3_REGION', 'us-east-1')

SIGNATURE_ERRORS = ('SignatureDoesNotMatch', 'InvalidSignature')


@unittest.skipIf(endpoint is None,
                 'AWS4_TEST_S3_ENDPOINT not set, skipping integration tests')
class S3CompatibleEndpoint_Test(unittest.TestCase):
    """
    Sign requests against a real SigV4 verifier listening on a non-default
    port, and require that it accepts our signature.

    """

    def auth(self):
        return AWS4Auth(access_id, secret_key, region, 's3',
                        session_token=os.getenv('AWS4_TEST_S3_SESSION_TOKEN'))

    def assertSignatureAccepted(self, status_code, body):
        for err in SIGNATURE_ERRORS:
            if err in body:
                self.fail(
                    'server rejected our signature with {} (HTTP {}). The Host '
                    'header we signed did not match the one we sent. Endpoint: '
                    '{}'.format(err, status_code, endpoint))

    def test_list_buckets_with_requests(self):
        response = requests.get(endpoint + '/', auth=self.auth())
        self.assertSignatureAccepted(response.status_code, response.text)

    def test_list_buckets_with_httpx(self):
        response = httpx.get(endpoint + '/', auth=self.auth())
        self.assertSignatureAccepted(response.status_code, response.text)

    def test_requests_and_httpx_both_accepted(self):
        """
        The same URL must be signed identically by both clients. Before the
        host header fix these diverged on non-default ports, so one client
        could work while the other failed against the same server.

        """
        r = requests.get(endpoint + '/', auth=self.auth())
        h = httpx.get(endpoint + '/', auth=self.auth())
        self.assertSignatureAccepted(r.status_code, r.text)
        self.assertSignatureAccepted(h.status_code, h.text)
        self.assertEqual(r.status_code, h.status_code)

    def test_explicit_host_header_still_accepted(self):
        """
        Setting Host explicitly is the documented workaround for the bug and
        has to keep working after the fix.

        """
        from urllib.parse import urlparse
        host = urlparse(endpoint).netloc
        response = requests.get(endpoint + '/', auth=self.auth(),
                                headers={'Host': host})
        self.assertSignatureAccepted(response.status_code, response.text)


if __name__ == '__main__':
    unittest.main()
