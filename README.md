# Overview 

This repository holds the scripts for parsing IOCs out of email feeds and Twitter streams, which are two common data feeds amongst threat intelligence professionals.

# Requirements

All of the scripts are written in Python3 and, for the most part, only depend on base modules provided by Python. One key exception is the `pandas` module, which can be installed via `pip` with `pip install pandas`. If you're using Anaconda, `pandas` should already be installed. 

In addition, if your enterprise utilizes Splunk, then you probably want to push the IOCs to a KV lookup within your Splunk instance. I have written the scripts to take advantage of my own personal wrapper around the Splunk API, called `splunk2`, which is included in this repo. 

# Output

All of these scripts will produce a standardized output. The hope is that this facilitates the easy aggregation of IOCs from multiple sources into a single source without losing visibility into where they came from. The following is a brief description of each field.

id: This is a unique identifier used to group IOCs together that came from the same item within a feed. For example, a single email in the H-ISAC feed might have several IOCs, such as sender, subject, and the hash of the attachment. In order to ensure analysts are able to maintain some context around IOCs, the `id` variable helps group those IOCs together. For emails, this value is pulled from the `ConversationID` attribute, and in the future, when Twitter is included, the value will come from the `tweetID`.

date_added: This is the date the IOC was added to the KV lookup or CSV file, which could differ from the date the IOC was received, but will mostly be the same as the `date_received` variable.

date_received: This is the date the IOC was received. For emails, this is grabbed from the `ReceivedTime` attribute, and for tweets will be grabbed from the `createdAt` value.

ioc: This is the actual IOC identified in feed. As of right now, IPs, hashes, URLs, and emails are captured. An attempt is made to "refang" the values so that they can be efficiently utilized in analyses.

platform: The actual feed from which the IOC came. Any IOC that comes from an H-ISAC email will have the value "H-ISAC" in the `platform` variable.

source: This is the name of the individual contributor that provided the IOC. For emails, this is the sender, which will sometimes be a name and other times be an email address. For tweets, this will be the handle of the user that tweeted the content. The sole purpose of this field is to enhance the ability to go back to the original source of the IOC and ensure it's validity or enrich the context.

tag: Any relevant hashtags that were in the tweet from which the IOC came. For emails, this field will simply be "N/A".

type: The type of IOC that was captured. This field can take the value of "ip", "hash", "url", or "email".

# Known issues

Refanging - There is no standard around how an analyst defangs an IOC, and as a result there is no standard way to reverse those efforts. These scripts make a concerted effort to do so, being somewhat lax on where the defanging can take place, but robust enough to ensure no valid emails make it through. However, not all versions of defanging can be accounted for, and thus some effort on your part to standardize this would go a long way. The preferred method for defanging an IOC is to replace "http" with "hxxp", and to wrap all . characters in brackets, resulting in the following examples.

```
URL   - hxxps://www[.]google[.]com
IP    - 127[.]0[.]0[.]1
Email - my[.]email@somedomain[.]com
```

Emails - Some email signatures include the sender's email address. Because the scripts currently look for IOCs using regular expressions, these emails will be picked up as well, with no way of parsing them out in any automatic fashion, which will lead to false positives any time an email comes from that sender. One way to avoid this is to standardize the format by which IOCs are provided in these feeds. I have several ideas on how to do this, but think it's best to be done via a conversation.

Other issues - For any other issues, please utilize the [Issues](https://github.com/potentpwnables/pyioc/issues) tab to let me know what's going on. I'll do my best to remedy the issue as soon as possible. Feedback and feature requests are always welcome as well.

# Usage

_Note: All scripts create a metadata file named after the script, which is a json file that holds some information about the script. Most notably, it holds the last run time, which is used to identify which emails need to be parsed in order to avoid duplication and redundant processing._

#### h-isac.py

This script requires a single parameter be passed, as well as an optional parameter. The required parameter is the folder where the emails from H-ISAC are sent. This folder *must* be a folder nested under your primary inbox (i.e. the inbox associated with your corporate email address). The optional parameter is the file path that points to your Splunk config file. If this parameter is not passed, the IOCs are saved to a CSV in the working directory with the name "h-isac-iocs-$date.csv", where `\$date` is in the form `%Y%m%d`.

Below is an example of a Splunk config file, as well as the command line syntax for utilizing the script.

###### Splunk config

```
{"username": "myusername",
 "password": "supersecretpassword",
 "app": "search",
 "kv_store": "iocs"
 }
 ```

###### Command line usage

```
# without the optional parameter
python3 h-isac.py "H-ISAC"

# with the optional parameter
python3 h-isac.py "H-ISAC" --splunk "c:/path/to/splunk_file.json"
```