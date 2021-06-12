import tweepy
import json
import re
import splunk2
import requests
from bs4 import BeautifulSoup as BS
from urllib.parse import urlparse
import sys


class Firehose(tweepy.StreamListener):
    def __init__(self, splunk):
        super(Firehose, self).__init__()
        self.splunk = splunk
        
    def on_error(self, status):
        print(status)
    
    def on_data(self, data):
        tweet = json.loads(data)
        
        # Exclude retweets
        if tweet['retweeted'] or tweet['text'].startswith('RT @'):
            return True
            
        # extract pertinent information
        created_at = tweet['created_at']
        _id = tweet['id']
        try:
            text = tweet['extended_tweet']['full_text'].replace('\r', '').replace('\n', ' ')
        except KeyError:
            text = tweet['text'].replace('\r', '').replace('\n', ' ')
            if len(text) > 140:
                print("Tweet is truncated, but extended_tweet isn't available...")
        user = tweet['user']['screen_name']
        hashtags = ';'.join([hashtag['text'] for hashtag in tweet['entities']['hashtags']])
        urls = ';'.join([url['expanded_url'] for url in tweet['entities']['urls']])
        
        # extract IOCs and append other relevant information
        iocs = self.extract_iocs(text, urls)
        iocs['created_at'] = created_at
        iocs['id'] = _id
        iocs['tags'] = hashtags
        iocs['user'] = user
        
        # push IOC dictionary to KV store
        self.dict_to_kv(iocs)
        return True
        
    def extract_iocs(self, text, links):
        links = [link for link in links.split(';') if 'pastebin' in link]
        if len(links) > 1:
            print('Unhandled situation: More than one pastebin link in a single tweet.')
        link = links[0] if links else links
        
        IP = r'((?:^|\b)(?:\d{1,3}\.){3}\d{1,3}(?:\b|$))'
        HASH = r'((?:^|\b)[a-fA-F0-9]{32,64}(?:\b|$))'
        URL = r'((?:^|\b)(?:h[xX]{2}ps?:|meows?:)?//(?:[A-Za-z0-9_\[\]#&,;=./-]+(?:\[?\.\]?)?)+(?:\b|$))'
        
        ips = re.findall(IP, text)
        hashes = re.findall(HASH, text)
        urls = re.findall(URL, text)
        
        if link:
            sorted_iocs = self.get_iocs(link)
        else:
            sorted_iocs = {'hashes': [], 'urls': [], 'ips': []}
            
        sorted_iocs['ips'].extend(ips)
        sorted_iocs['urls'].extend(urls)
        sorted_iocs['hashes'].extend(hashes)
        return sorted_iocs
        
    def get_iocs(self, url):
        # this function follows the URL to pastebin and extracts the information from the post
        response = requests.get(url)
        soup = BS(response.content, 'html.parser')
        items = soup.select('#code_frame2 ol > li > div')
        values = [item.text for item in items]
        return self.sort_iocs(values)
        
    def sort_iocs(self, iocs):
        sorted_iocs = {'hashes': [], 'urls': [], 'ips': [], 'unmatched': []}
        for ioc in iocs:
            # if there's a . in the IOC then it's most likely an IP or URL
            if '.' in ioc:
                # clean the ioc for conformity
                ioc = urlparse(ioc).netloc
                try:
                    tmp = list(map(int, ioc.split('.')))
                    sorted_iocs['ips'].append(ioc)
                except:
                    sorted_iocs['urls'].append(ioc)
            # otherwise it's a file hash or random text
            else:
                # check if it's a file hash
                match = re.match(r'[a-zA-Z0-9]{32,64}', ioc)
                if match:
                    sorted_iocs['hashes'].append(ioc)
                # add the ioc no matter what so we can check the logic  
                else:
                    sorted_iocs['unmatched'].append(ioc)
        return sorted_iocs
        
    def dict_to_kv(self, iocs):
        # iocs is the dictionary that holds the pertinent data from any processed tweets found in the stream
        hashes = iocs['hashes']
        urls = iocs['urls']
        ips = iocs['ips']
        tags = iocs['tags']
        source = iocs['user']
        date_added = iocs['created_at']
        ID = iocs['id']
        for h in hashes:
            payload = self.generate_payload(date_added, tags, source, ID, h, 'hash')
            self.push_to_kv(self.splunk, payload)
        for u in urls:
            payload = self.generate_payload(date_added, tags, source, ID, u, 'url')
            self.push_to_kv(self.splunk, payload)
        for i in ips:
            payload = self.generate_payload(date_added, tags, source, ID, i, 'ip')
            self.push_to_kv(self.splunk, payload)
    
    
    def generate_payload(self, date, tags, source, ID, ioc, ioc_type):
        data = '"id": "{ID}", "date_added": "{date}", "type": "{ioc_type}", "tag": "{tags}", "ioc": "{ioc}", "source": "{source}"'.format(ID=ID, date=date, tags=tags, source=source, ioc=ioc, ioc_type=ioc_type)
        data = '{' + data + '}'
        return data
    
    
    def push_to_kv(self, splunk, data):
        results = splunk.post('servicesNS/nobody/<splunk app name>/storage/collections/data/<kv lookup table name>', headers={'Content-Type': 'application/json'}, data=data)
        return None


def connect(cred_file, app):
    if not cred_file.endswith("json"):
        print("The credential file must be a JSON file")
        return None
        
    # try to load creds and authorize the Twitter API
    with open(cred_file, 'r') as f:
        creds = json.load(f)
        creds = creds[app]
    try:
        auth = tweepy.OAuthHandler(creds["consumer_key"], creds["consumer_secret"])
        auth.set_access_token(creds["access_token"], creds["access_secret"])
    except KeyError:
        print("Your credential file must have the consumer_key, consumer_secret, access_token, and access_secret keys")
        return None
    return tweepy.API(auth)

def connect_to_splunk(cred_file):
    with open(cred_file, 'r') as f:
        creds = json.load(f)
    api = splunk2.API()
    api.authenticate(creds['username'], creds['password'])
    return api

def main():
    api = connect('/path/to/twitter/api_creds.json')
    splunk = connect_to_splunk('/path/to/splunk_creds.json')
    stream = tweepy.Stream(auth=api.auth, listener=Firehose(splunk))
    stream.filter(track=['#emotet', '#hancitor', '#lokibot', '#malspam', '#ransomware', '#customtag'])
    
    
if __name__ == '__main__':
    main()
