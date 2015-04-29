"""
Amazon Web Services version 4 authentication for the Python Requests_
library.

.. _Requests: https://github.com/kennethreitz/requests

Features
--------
* Requests authentication for all AWS services that support AWS auth v4
* Generation of re-usable signing keys with full scope customisation

Supported Services
------------------
This package has been tested as working against:

AppStream, Auto-Scaling, CloudFormation, CloudFront, CloudHSM, CloudSearch,
CloudTrail, CloudWatch Monitoring, CloudWatch Logs, CodeDeploy, Cognito
Identity, Cognito Sync, Config, DataPipeline, Direct Connect, DynamoDB, Elastic
Beanstalk, ElastiCache, EC2, EC2 Container Service, Elastic Load Balancing,
Elastic MapReduce, Elastic Transcoder, Glacier, Identity and Access Management
(IAM), Key Management Service (KMS), Kinesis, Lambda, Opsworks, Redshift,
Relational Database Service (RDS), Route 53, Simple Storage Service (S3),
Simple Notification Service (SNS), Simple Queue Service (SQS), Storage Gateway,
Security Token Service (STS)

The following services do not support AWS auth version 4 and are not usable
with this package:

Simple Email Service (SES), Simple Workflow Service (SWF), Import/Export,
SimpleDB, DevPay, Mechanical Turk

The AWS Support API has not been tested as it requires a premium subscription.

Installation
------------
Install via pip:

.. code-block:: bash

    $ pip install requests-aws4auth

requests-aws4auth requires the Requests_ library by Kenneth Reitz.

requests-aws4auth is tested on Python 2.7 and 3.2 and up.

Basic usage
-----------
.. code-block:: python

    >>> import requests
    >>> from requests_aws4auth import AWS4Auth
    >>> endpoint = 'http://s3-eu-west-1.amazonaws.com'
    >>> auth = AWS4Auth('<ACCESS ID>', '<ACCESS KEY>', 'eu-west-1', 's3')
    >>> response = requests.get(endpoint, auth=auth)
    >>> response.status_code
    200

This example would list your buckets in the ``eu-west-1`` region of the Amazon
S3 service.

``AWS4Auth`` objects
--------------------
Supply an ``AWSAuth`` instance as the ``auth`` argument to a Requests call
to handle AWS authentication. ``AWS4Auth`` instances can be created by
supplying scope parameters directly or by using a pre-generated signing key:

.. code-block:: python

    >>> auth = AWS4Auth(access_id, access_key, region, service)

or:

.. code-block:: python

    >>> auth = AWSAuth(access_id, signing_key)

``access_id`` - this is your AWS access ID

``access_key`` - this is your AWS access key

``region`` - the region you're connecting to, as per the list at:
http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region.  e.g.
``us-east-1``. For services which don't require a region (e.g. IAM), use
``us-east-1``

``service`` - the name of the service you're connecting to, as per endpoints
at: http://docs.aws.amazon.com/general/latest/gr/rande.html.  e.g.
``elasticbeanstalk``.

``signing_key`` - an ``AWS4SigningKey`` instance.

You can reuse ``AWS4Auth`` instances to authenticate as many requests as you
need. Note signing keys (and thus ``AWS4Auth`` instances) expire after 7 days.

``AWS4SigningKey`` objects
--------------------------
Used to create a signing key which can be distributed to provide scoped access
to AWS resources:

.. code-block:: python

    >>> from requests_aws4auth import AWS4SigningKey
    >>> key = AWS4SigningKey(access_key, region, service[, date])

The first four arguments are required, ``date`` is optional. ``access_key``,
``region`` and ``service`` are the same as for ``AWS4Auth``. ``date`` is an
8-digit date of the form ``YYYYMMDD``. This is the starting date for the
signing key's validity, signing keys are valid for 7 days from this date. If
``date`` is not supplied the current date is used.

Once instantiated the key string itself is stored in the object's ``key``
attribute. The ``access_key`` is not stored in the object.

Multi-threading / processing
-------------------------
``AWS4Auth`` and ``AWS4SigningKey`` instances should be fine to share across
multiple threads and processes so long as threads/processes don't mess with the
internal variables.

Testing
-------
A test suite is included in the test folder.

The package passes all tests in the AWS auth v4 `test suite`_, and contains
tests against the supported live services. See docstrings in
``test/requests_aws4auth_test.py`` for details about running the tests.

Connection parameters are included in the tests for the AWS Support API, should
you have access and want to try it. The documentation says it supports auth v4
so it should work if you have a subscription. Do pass on your results!

.. _test suite: http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html

Unsupported AWS features / todo
-------------------------------
* Currently does not support Amazon S3 chunked uploads
* Requires Requests library to be present even if only using
  ``AWS4SigningKey``

"""

# Licensed under the MIT License:
# http://opensource.org/licenses/MIT


from .aws4auth import AWS4Auth
from .aws4signingkey import AWS4SigningKey
del aws4auth
del aws4signingkey

__version__ = '0.5'
