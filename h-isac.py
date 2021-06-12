import win32com.client
import datetime as dt
import pandas as pd
import splunk2
import argparse
import json
import os
import re
import sys

def push_to_splunk(data, config_file):
    # ensure the config file can be loaded
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        raise ValueError("{} does not exist. Please try again with the correct file path.".format(config_file))
        
    # ensure the appropriate values are in the config file
    want = set(['username', 'password', 'app', 'kv_store'])
    have = set(list(config.keys()))
    if want - have:
        raise KeyError("Required keys missing. Make sure your config file has username, password, app, and kv_store.")
    
    api = splunk2.API()
    api.authenticate(config["username"], config["password"])
        
    ENDPOINT = "servicesNS/nobody/{}/storage/collections/data/{}/batch_save".format(config["app"], config["kv_store"])
    HEADERS = {"Content-Type": "application/json"}
    DATA = []
    for row in range(data.shape[0]):
        x = data.loc[row, :].to_json()
        DATA.append(x)
        # it is unlikely that there will be 1,000 IOCs at once, but that's the limit for Splunk's,
        # batch save at one time, so we have to handle it here.
        if len(DATA) == 1000:
            DATA = '[' + ', '.join(DATA) + ']'
            api.post(ENDPOINT, headers=HEADERS, data=DATA)
            DATA = []
    # need to upload any final records (e.g. the last 434 records if there are 5,434 records) 
    if len(DATA) > 0:
        DATA = '[' + ', '.join(DATA) + ']'
        api.post(ENDPOINT, headers=HEADERS, data=DATA)
    return True
    
def refang(ioc):
    ioc = re.sub(r"h[xX]{2}p(?=[s:])", "http", ioc)
    ioc = re.sub(r"\[([.@])\]", r"\1", ioc)
    return ioc

def clean_text(body):
    """
    This function takes in the an email and removes any text from
    prior email communications. For example, if the email is a reply
    to a prior email with indicators, it will look for From: H-ISAC Amber
    in the body of the email, and remove any text from that point onward.
    The point in doing this is to try to ensure we don't get duplicate
    IOCs from parsing a response email to an Indicator email. But we don't
    want to rely on the subject line containing "Re", because a user could
    remove it.
    """
    match = re.search(r"From: H-ISAC Amber", body)
    if match:
        lines = body.split("\n")
        idx = [i for i,s in enumerate(lines) if "From: H-ISAC Amber" in s][0]
        body = "\n".join(lines[:idx])
    return body

def extract_iocs(message):
    IP = r"((?:^|\b)(?:\d{1,3}\[?\.\]?){3}\d{1,3}(?:\b|$))"
    HASH = r"((?:^|\b)[a-fA-F0-9]{32,64}(?:\b|$))"
    URL = r"((?:^|\b)(?:h[xX]{2}ps?:|meows?:)?//(?:[A-Za-z0-9_\[\]#&,;=./-]+(?:\[?\.\]?)?)+(?:\b|$))"
    EMAIL = r"((?:^|\b)(?:[^\s]+?\@(?:.+?)\[\.\][a-zA-Z]+)(?:$|\b))"
    
    body = clean_text(message.Body)
    ips = re.findall(IP, body)
    hashes = re.findall(HASH, body)
    urls = re.findall(URL, body)
    emails = re.findall(EMAIL, body)
    
    # clean up the iocs
    ips = [refang(ip) for ip in ips]
    urls = [refang(url) for url in urls]
    emails = [refang(email).replace("mailto:", "") for email in emails]
    
    iocs = {"ip": [], "hash": [], "url": [], "email": []}
    iocs["ip"].extend(ips)
    iocs["hash"].extend(hashes)
    iocs["url"].extend(urls)
    iocs["email"].extend(emails)
    return iocs

def parse_message(message):
    dfs = []
    iocs = extract_iocs(message)
    eid = message.ConversationID
    source = str(message.Sender)
    platform = "H-ISAC"
    dr = message.ReceivedTime.strftime("%Y-%m-%d")
    da = dt.datetime.now().strftime("%Y-%m-%d")
    
    for x in ["ip", "hash", "url", "email"]:
        if iocs[x]:
            data = {"id": eid, "source": source, "platform": platform,
                    "date_received": dr, "date_added": da,
                    "ioc": iocs[x], "type": x, "tag": "N/A"}
            df = pd.DataFrame.from_dict(data)
            dfs.append(df)
    # if the email is a reply to an email that had indicators, it's likely
    # the the email itself will not have IOCs, and thus dfs will be empty.
    if dfs:
        df = pd.concat(dfs, ignore_index=True)
    else:
        df = pd.DataFrame()
    return df

def get_messages(folder):
    # connect to Outlook
    obj = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
    # GetDefaultFolder(6) gets your main Inbox folder
    folder = obj.GetDefaultFolder(6).Folders(folder)
    messages = folder.items
    return messages
    
def get_metadata():
    # read in meta data if it exists, otherwise create it
    fpath = os.path.expanduser("~/pyioc_hisac_meta.json")
    try:
        with open(fpath, "r") as f:
            meta = json.load(f)
    except FileNotFoundError:
        now = dt.datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")
        meta = {"first_run": now, 
                "last_run": None, 
                "processed_emails": 0, 
                "iocs": {"ips": 0, "hashes": 0, "urls": 0, "emails": 0}}
        with open(fpath, "w") as f:
            json.dump(meta, f)
    return meta

def main(args):
    meta = get_metadata()
    last_run = meta["last_run"] # get the last run time before it's overwritten
    
    # get emails with IOCs and extract them
    messages = get_messages(args.folder)
    meta["last_run"] = dt.datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")
    
    # if the script has been run before, ignore all emails that have been
    # previously processed. If this is the first run, all emails will be
    # analyzed.
    if last_run is not None:
        messages = messages.Restrict("[ReceivedTime] >= '{}'".format(last_run))
        
    all_data = []
    message = messages.GetFirst()
    while message:
        if "indicator" in message.Subject.lower():
            data = parse_message(message)
            all_data.append(data)
        message = messages.GetNext()
    if all_data:
        data = pd.concat(all_data, ignore_index=True)
        if args.splunk is not None:
            push_to_splunk(data, args.splunk)
        else:
            date = dt.datetime.now().strftime("%Y%m%d")
            data.to_csv("amber_list_iocs_{}.csv".format(date), index=False)
    
        # update the meta data
        meta["iocs"]["ips"]    += data.loc[data["type"] == "ip", :].shape[0]
        meta["iocs"]["hashes"] += data.loc[data["type"] == "hash", :].shape[0]
        meta["iocs"]["urls"]   += data.loc[data["type"] == "url", :].shape[0]
        meta["iocs"]["emails"] += data.loc[data["type"] == "email", :].shape[0]
        
    meta["processed_emails"] += len(messages)
    fpath = os.path.expanduser("~/pyioc_hisac_meta.json")
    with open(fpath, "w") as f:
        json.dump(meta, f)
    print("Done.")

if __name__ == "__main__":
    description = """
    This script is meant to be a relatively simply extraction tool to parse IOCs from
    the H-ISAC Amber List emails. It looks for emails with the word "indicator" in the
    subject (not case-sensitive) within a specified folder and extracts IPs, hashes,
    URLs, and emails from the body of the email. If you use Splunk, you can specify that
    the IOCs should be pushed to Splunk to a pre-specified KV Store lookup table; 
    otherwise the IOCs will be saved to a CSV and saved in the current directory with
    today's date.
    
    NOTES:
        1) This script requires you to be using Outlook as your email application.
        2) The script reads in a json file that is saved as ~/pyioc_meta.json, which
           holds information on the last time the script was run, the first time it 
           was run, the number of emails processed, and the number of IOCs extracted 
           broken down by type.
        3) If utilizing the feature to push to Splunk, it assumes you're using the 
           splunk2 script, which can be found here: 
                       https://github.com/potentpwnables/py-splunk
           This is different from the Python SDK provided by Splunk. If using the SDK,
           you can modify the push_to_splunk() function to accommodate that.
    """
    parser = argparse.ArgumentParser(description=description, prog="h-isac.py")
    parser.add_argument("folder", type=str, help="Specify the folder that holds the H-ISAC emails")
    parser.add_argument("--splunk", type=str, default=None, help="Specify the file location of the config file that hase your username, password, app name, and kv store name. Leave empty if not using Splunk")
    args = parser.parse_args()
    
    # ensure a proper config file was passed
    if not args.splunk.endswith("json"):
        raise ValueError("{} does not appear to be a JSON file.".format(args.splunk))
    main(args)
