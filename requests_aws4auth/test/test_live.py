#!/usr/bin/env python
# coding: utf-8

"""
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

import unittest
import os
import json

live_access_id = os.getenv('AWS_ACCESS_ID')
live_secret_key = os.getenv('AWS_ACCESS_KEY')


@unittest.skipIf(live_access_id is None or live_secret_key is None,
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
        'Elastic Beanstalk': 'elasticbeanstalk.us-east-1.amazonaws.com/'
                             '?Action=ListAvailableSolutionStacks&Version=2010-12-01',
        'ElastiCache': 'elasticache.us-east-1.amazonaws.com/?Action=DescribeCacheClusters&Version=2014-07-15',
        'EC2': 'ec2.us-east-1.amazonaws.com/?Action=DescribeRegions&Version=2014-06-15',
        'EC2 Container Service': 'ecs.us-east-1.amazonaws.com/?Action=ListClusters&Version=2014-11-13',
        'Elastic Load Balancing': 'elasticloadbalancing.us-east-1.amazonaws.com/'
                                  '?Action=DescribeLoadBalancers&Version=2012-06-01',
        'Elastic MapReduce': 'elasticmapreduce.us-east-1.amazonaws.com/?Action=ListClusters&Version=2009-03-31',
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
        'Relational Database Service (RDS)': 'rds.us-east-1.amazonaws.com/'
                                             '?Action=DescribeDBInstances&Version=2012-09-17',
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
        auth = AWS4Auth(live_access_id, live_secret_key, region, service)
        response = requests.request(method, url, auth=auth,
                                    data=body, headers=headers)
        # suppress socket close warnings
        response.connection.close()
        self.assertTrue(response.ok)

    def test_mobileanalytics(self):
        url = 'https://mobileanalytics.us-east-1.amazonaws.com/2014-06-05/events'
        service = 'mobileanalytics'
        region = 'us-east-1'
        dt = datetime.datetime.utcnow()
        date = dt.strftime('%Y%m%d')
        sig_key = AWS4SigningKey(live_secret_key, region, service, date)
        auth = AWS4Auth(live_access_id, sig_key)
        headers = {'Content-Type': 'application/json',
                   'X-Amz-Date': dt.strftime('%Y%m%dT%H%M%SZ'),
                   'X-Amz-Client-Context':
                       json.dumps({
                           'client': {'client_id': 'a', 'app_title': 'a'},
                           'custom': {},
                           'env': {'platform': 'a'},
                           'services': {}})}
        body = json.dumps({
                          'events': [{
                                     'eventType': 'a',
                                     'timestamp': dt.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                                     'session': {}
                                     }]
                          })
        response = requests.post(url, auth=auth, headers=headers, data=body)
        response.connection.close()
        self.assertTrue(response.ok)

