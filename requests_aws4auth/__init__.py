"""
requests-aws4auth
=================

Amazon Web Services version 4 authentication for the Python requests module.

requests-aws4auth is an authentication module for the `requests`_ Python
library which provides version 4 authentication for the Amazon Web Services
(AWS) REST `APIs`_.

requests-aws4auth is `MIT Licensed`_.

.. _requests: https://github.com/kennethreitz/requests
.. _APIs: http://docs.aws.amazon.com/general/latest/gr/rande.html
.. _MIT Licensed: http://en.wikipedia.org/wiki/MIT_License

Features
--------
* Authentication for all AWS `regions`_ and `services`_
* Generation of signing keys with full scope customisation

.. _regions: http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
.. _services: http://docs.aws.amazon.com/general/latest/gr/rande.html

Basic usage
-----------
::

    >>> import requests
    >>> from requests_aws4auth import AWS4Auth
    >>> auth = AWS4Auth('<ACCESS ID>', '<ACCESS KEY>', 'eu-west-1', 's3')
    >>> endpoint = 'http://s3-eu-west-1.amazonaws.com'
    >>> response = requests.get(endpoint, auth=auth)
    >>> response.status_code
    200

This example would list your buckets in the eu-west-1 region of the Amazon S3
service.

Installation
------------
Install via pip::

    $ pip install requests-aws4auth

requests-aws4auth requires the `requests`_ library by Kenneth Reitz.

AWS4Auth objects
----------------
Instances can be created by supplying scope parameters directly or by
using a pre-generated signing key::

    >>> auth = AWS4Auth(access_id, access_key, region, service)

or::

    >>> auth = AWSAuth(access_id, signing_key)

**access_id** -- This is your AWS access ID

**access_key** -- This is your AWS access key

**region** -- The region you're connecting to, as per the list at
http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region.
e.g. us-east-1. For services which don't require a region (e.g. IAM), use
us-east-1

**service** -- The name of the service you're connecting to, as per endpoints
at: http://docs.aws.amazon.com/general/latest/gr/rande.html.  e.g.
elasticbeanstalk.

**signing_key** -- A signing key as created by AWS4SigningKey.

You can reuse AWS4Auth instances to authenticate as many requests as you need.

AWS4SigningKey objects
----------------------
Used to create a signing key which can be distributed to provide scoped access
to AWS resources::

    >>> from requests_aws4auth.aws4signingkey import AWS4SigningKey
    >>> AWS4SigningKey(access_key, region, service[, date])

The first four arguments are required, date is optional. access_key, region and
service are the same as for AWS4Auth. date is an 8-digit date of the form
YYYYMMDD. This is the starting date for the signing key's validity, signing
keys are valid for 7 days from this date. If date is not supplied the current
date is used.

Once instantiated the key string itself is stored in the object's key
attribute. The access_key is not stored in the object.

Multithreading/processing
-------------------------
AWS4Auth instances should be fine to share across multiple threads and
processes so long as threads/processes don't mess with the internal variables.

Unsupported AWS features / todo
-------------------------------
* Currently does not support Amazon S3 chunked uploads.
* Requires requests library to be present even if only using AWS4SigningKey.

"""
from .aws4auth import AWS4Auth
del aws4auth

