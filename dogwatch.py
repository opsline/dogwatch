#!/usr/bin/python

import sys
import os
import datetime
import logging
import traceback
import boto
import boto.utils
import boto.ec2.cloudwatch as cloudwatch
from optparse import OptionParser
from dogapi import dog_http_api as api
from yaml import load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

###############################################################################
def main():
    config = {}
    parser = OptionParser(usage='Usage: %prog [options]\n')
    parser.add_option('-c', '--config', default='',
                      action='store', type='string', dest='config',
                      help='Configuration file')
    parser.add_option('-v', '--verbose', default=False,
                      action='store_true', dest='verbose',
                      help='Verbose output')
    (options, args) = parser.parse_args()

    if options.verbose:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO

    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='%y/%m/%d %H:%M:%S',
                        level=loglevel)

    if options.config:
        if os.path.exists(options.config):
            config = load(file(options.config, 'r'), Loader=Loader)
        else:
            print('ERROR: configuration file %s does not exist' % \
                options.config)
            sys.exit(1)

    # initialize datadog api connection
    if config.has_key('datadog'):
        api.api_key = config['datadog']['api_key']
        api.application_key = config['datadog']['application_key']
    else:
        logging.error('missing datadog configuration')
        sys.exit(1)
    api.timeout = 30

    # initialize cloudwatch connection
    md = boto.utils.get_instance_metadata()
    try:
        iam_role = md['iam']['security-credentials'].keys()[0]
        iam_cred = md['iam']['security-credentials'][iam_role]
    except:
        iam_cred = None
    if iam_cred is not None:
        cw = cloudwatch.connect_to_region(
             config['aws']['region'],
             aws_access_key_id=iam_cred['AccessKeyId'],
             aws_secret_access_key=iam_cred['SecretAccessKey'],
             security_token=iam_cred['Token'])
    elif config.has_key('aws'):
        cw = cloudwatch.connect_to_region(
             config['aws']['region'],
             aws_access_key_id=config['aws']['access_key_id'],
             aws_secret_access_key=config['aws']['secret_access_key'])
    else:
        logging.error('missing aws configuration')
        sys.exit(1)

    end = int(datetime.datetime.utcnow().strftime('%s'))
    start = end - 600

    for metric_name in config['metrics'].keys():
        logging.info('processing %s' % metric_name)
        metric_def = config['metrics'][metric_name]

        value = None

        # get last value from datadog
        logging.debug('getting value from datadog')
        try:
            ddresult = api.http_request('GET', '/query',
                **{'from': start, 'to': end,
                    'query': metric_def['datadog']['query']})
            timestamp = datetime.datetime.fromtimestamp(
                int(ddresult['series'][0]['pointlist'][-1][0]) / 1000)
            value = ddresult['series'][0]['pointlist'][-1][1]
        except:
            logging.error('failed getting value from datadog')
            traceback.print_exc(file=sys.stderr)

        # if datadog failed, get last value from cloudwatch for repeat
        if value is None:
            logging.warn('getting last value from cloudwatch')
            try:
                cwresult = cw.get_metric_statistics(60,
                    datetime.datetime.utcnow() - datetime.timedelta(hours=1),
                    datetime.datetime.utcnow(),
                    metric_def['cloudwatch']['name'],
                    metric_def['cloudwatch']['namespace'],
                    ['Average'],
                    dimensions=metric_def['cloudwatch']['dimensions'],
                    unit=metric_def['cloudwatch']['unit'])
                cwresult.sort(key=lambda x: x['Timestamp'])
                timestamp = datetime.datetime.utcnow()
                value = cwresult[-1]['Average']
            except:
                logging.error('failed getting last value from cloudwatch')
                traceback.print_exc(file=sys.stderr)
                continue

        logging.info('got data point: %s @ %s' % (value, timestamp))

        # insert cloudwatch value
        logging.debug('sending value to cloudwatch')
        try:
            cw.put_metric_data(
                metric_def['cloudwatch']['namespace'],
                metric_def['cloudwatch']['name'],
                timestamp=timestamp,
                value=value,
                unit=metric_def['cloudwatch']['unit'],
                dimensions=metric_def['cloudwatch']['dimensions'],
                statistics=None)
        except:
            logging.error('failed sending value to cloudwatch')
            traceback.print_exc(file=sys.stderr)
            continue

##############################################################################
if __name__ == '__main__':
    main()

##############################################################################
