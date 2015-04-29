Release History
---------------

0.5 (29-04-2015)
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
