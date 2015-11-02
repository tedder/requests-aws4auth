Release History
---------------

0.7 (2015-11-02)
++++++++++++++++

**Bugfixes**

- Fixed percent encoded characters in URL paths not being encoded again
  for signature generation, as is expected for all services except S3.
  This was causing authentication failures whenever these characters
  appeared in a URL. Thanks to ipartola and cristi23 for the report.

- Two bugfixes for ElasticSearch, thanks to Matthew Thompson for both:
  * No longer setting body to b'' during signing if it's None
  * Now stripping port from URL netloc for signature generation

**Modules**

- Upgraded the included version of six.py to 1.10

**Tests**

- Fixed a couple of broken Unicode tests on Python 2

- Added a couple more tests for encoding Unicode request bodies


0.6 (2015-09-07)
++++++++++++++++

**Bugfixes**

- Included HISTORY.rst in built package to fix pip source install failure.
  Thanks to Beirdo for the bug report.


0.5 (2015-04-29)
++++++++++++++++

**Bugfixes**

- Fixed bug when uploading to S3 with x-amz-acl header which caused
  authentication failure - headers used in signature are now: host,
  content-type and all x-amz-* headers (except for x-amz-client-context which
  breaks Mobile Analytics auth if included)

**Docs**

- Minor docstring and comment updates

**License**

- Changed content of LICENSE to vanilla MIT license
