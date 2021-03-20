#!/usr/bin/env python

import boto3
import botocore
import argparse
import csv
import logging
import datetime
import click
import yaml
import os
import time
import sys
from colorama import init
init()
from colorama import Fore, Back, Style
from pathlib import Path
import json
from datetime import datetime

###
### This script checks cloudtrail events for an instance in every aws account
###

data_folder = Path("trail/logs")
logfile = data_folder / "trailforinstance.log"

logging.basicConfig(filename=logfile, filemode='a', format='%(levelname)s - %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

targetaccount = 'allaccounts'

# GLOBAL SESSION
sts = boto3.client('sts')

def aws_session(account_id, session_name, role_name):
    """
    Function that creates the boto3 session by assuming a cross account role

    Uses boto3 to make calls to the STS API

    """
    role_arn = 'arn:aws:iam::' + account_id + ':role/' + role_name
    logger.info('Trying to assume role: ' + str(role_arn))
    if account_id:
        try:
            response = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            session = boto3.Session(
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken'])
            return session
        except Exception as e:
            print("unable to assume role")
            logger.error('unable to assume role: ' + str(e))
    else:
        print("account_id passed to aws session func was empty")
        logger.error('account_id passed to `aws_session` func was empty!')

def account_name(session):
    """
    Function that resolves the account name (alias) to make output human friendly

    Uses boto3 to make calls to the IAM API

    """
    iam = session.client('iam')
    account_name = "Null"
    response = iam.list_account_aliases()
    logger.info('account_name response:' + str(response))
    if 'AccountAliases' in response and response['AccountAliases']:
        account_name = response['AccountAliases'][0]
    return account_name

def get_instances(filters=[]):
    reservations = {}
    try:
        reservations = ec2.describe_instances(
            Filters=filters
        )
    except botocore.exceptions.ClientError as e:
        print(e.response['Error']['Message'])

    instances = []
    for reservation in reservations.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            instances.append(instance)
    return instances

def main():

    accounts=[account ids]


    for account in accounts:
        logger.info('dispatching session call for account: ' + str(account) )
        if str(account) == str(config['sourceaccount']):
            session = boto3.Session(region_name=config['region'])
        else:
            session = aws_session(account_id=str(account), session_name='assume-role', role_name = role_name)
        if session:
            AccountName = account_name(session)
            global ec2
            ec2 = session.client('ec2', region_name='ap-southeast-2')
            instances = get_instances()
            ct_conn = session.client(service_name='cloudtrail',region_name='ap-southeast-2')
            for instance in instances:
                instid=instance.get('InstanceId')
                events_dict= ct_conn.lookup_events(LookupAttributes=[{'AttributeKey':'ResourceName', 'AttributeValue':instid}])
                endtime = datetime.utcnow()
                for data in events_dict['Events']:
                    json_file= json.loads(data['CloudTrailEvent'])
                    ENAME=json_file['eventName']
                    if ENAME == 'RunInstances': 
                        print (ENAME)
        else:
            print("did not get session")
            sys.exit()            
if __name__ == "__main__":
    main()