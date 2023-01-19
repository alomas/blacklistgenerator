import configparser
import os
import boto3
from botocore.exceptions import ClientError


def startup():
    config = configparser.ConfigParser()
    config.read('blacklistgenerator.cfg')
    iptable = "None"
    awsregion = "us-east-1"
    try:
        iptable = config['blacklist']['iptable']
        awsregion = config['blacklist']['awsregion']
    except KeyError as e:
        print("No config file, so pulling info from my user's AWS tags.")
        iam = boto3.resource("iam")
        user = iam.CurrentUser()
        tagset = user.tags
        for tag in tagset:
            if tag['Key'] == 'AWSRegion':
                awsregion = tag['Value']
            if tag['Key'] == 'LogTable':
                iptable = tag['Value']
    config = {}
    config["iptable"] = iptable
    config["awsregion"] = awsregion
    return config

def getips(config, mincount):
    dynamodb = boto3.client("dynamodb", region_name=config["awsregion"])
    table = config["iptable"]
    try:
        response = dynamodb.scan(
            TableName = table
        )
        itemdict = response["Items"]
        newitemdict = {}
        for item in itemdict:
            itemcount = int(item["count"]["N"])
            srcip = item["srcip"]["S"]
            count = 0
            if srcip in newitemdict:
                count = newitemdict[srcip]
            newitemdict[item["srcip"]["S"]] = count + itemcount

        dynamodb = boto3.resource("dynamodb", region_name=config["awsregion"])
        tableobj = dynamodb.Table(table)
        newitems = []
        for item in newitemdict:
            if newitemdict[item] > 2:
                tempitem = {
                    "srcip": item,
                    "count": newitemdict[item]
                }
                for entry in itemdict:
                    if entry["srcip"]['S'] == item:
                        index = entry["FortiLogID"]["S"]
                        response = tableobj.get_item(Key={'FortiLogID': index}, TableName=table)
                        object = response["Item"]
                        object["status"] = "Banned"
                        response = tableobj.put_item(TableName=table, Item=object)
                        print(f'Updated entry for {index} to Banned')
                newitems.append(tempitem)
            else:
                totalcount = newitemdict[item]
                for entry in itemdict:
                    if entry["srcip"]['S'] == item:
                        index = entry["FortiLogID"]["S"]
                        response = tableobj.get_item(Key={'FortiLogID': index}, TableName=table)
                        if "Item" in response:
                            object = response["Item"]
                        else:
                            print(response)
                        object["total"] = totalcount
                        response = tableobj.put_item(TableName=table, Item=object)
                        print(f'Updated total for {index} to {totalcount}')
        return newitems

    except ClientError as e:
        print(e.response['Error']['Message'])
        print("No Item exists, yet")

def writeips(iplist):
    ipstring = ""
    for ip in iplist:
        ipstring += ip["srcip"] + "\n"
    print(ipstring)
    ipfile = os.getenv("ipfile")
    with open(ipfile, "w") as outfile:
        outfile.write(ipstring)

def main(name):
    config = startup()
    iplist = getips(config, 1)
    writeips(iplist)

if __name__ == '__main__':
    main('')

