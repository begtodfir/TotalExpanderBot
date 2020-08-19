# bot.py
import os
import requests
import discord
import json
import re
import urllib.parse
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
VT_KEY = os.getenv('VT_KEY')
VT_URL = os.getenv('VT_URL')
VT_ID_BASE = os.getenv('VT_ID_BASE')
REDIRECT_API = os.getenv('REDIRECT_API')

headers = {"x-apikey" : VT_KEY}

client = discord.Client()
  
def FindURL(string): 
    # findall() has been used  
    # with valid conditions for urls in string 
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex,string)       
    return [x[0] for x in url] 


def redirect_check(url):
    encoded_url = urllib.parse.quote(url)
    urls_analyzed = []
    response = requests.get(REDIRECT_API + encoded_url)
    for i in range(len(response.json()['data'])):
        url_to_analyze = response.json()['data'][i]['response']['info']['url']
        url_malicious_count = vt_check(url_to_analyze)
        url_entry = { 'url' : url_to_analyze, 'malicious_count' : url_malicious_count }
        urls_analyzed.append(url_entry)

    return urls_analyzed


def vt_check(exp_url):
    exp_url_vt = {"url": exp_url}
    vt_id = requests.post(VT_URL, data=exp_url_vt, headers=headers)
    vt_id_clean = vt_id.json()['data']['id']
    vt_response = requests.get(VT_ID_BASE + str(vt_id_clean), headers=headers)  
           
    if vt_response.status_code != requests.codes.ok:
        return None
    else:
        vt_response_json = json.loads(vt_response.content.decode('utf-8'))
        vt_response_malicious_count = vt_response_json['data']['attributes']['stats']['malicious']   
        return vt_response_malicious_count


@client.event
async def on_ready():
    print(f'{client.user} has connected to Discord!')

@client.event
async def on_message(message):
    if message.author == client.user:
        return
    if 'https://' not in message.content and 'http://' not in message.content:
        return
    elif 'https://bit.ly' not in message.content and 'https://t.co' not in message.content and 'https://goo.gl' not in message.content and 'https://ow.ly' not in message.content and 'https://tinyurl' not in message.content and 'https://buff.ly' not in message.content and 'https://bit.do' not in message.content and 'https://polr' not in message.content and 'http://bit.ly' not in message.content and 'http://t.co' not in message.content and 'http://goo.gl' not in message.content and 'http://ow.ly' not in message.content and 'http://tinyurl' not in message.content and 'http://buff.ly' not in message.content and 'http://bit.do' not in message.content and 'http://polr' not in message.content:
        return
    else:
        urls = FindURL(message.content)
        for url in urls:
            await message.channel.send('Starting analysis for `' + url + '`...')
            redirect_urls_analyzed = redirect_check(url)
            
            malicious_flag = False

            results = '```Original URL: ' + url + os.linesep + os.linesep
            for i in range(len(redirect_urls_analyzed)):
                if '0' not in str(redirect_urls_analyzed[i]['malicious_count']):
                    malicious_flag = True
                results += 'Redirect #' + str(i) + ': URL - ' + redirect_urls_analyzed[i]['url'] + ', Detected by: ' + str(redirect_urls_analyzed[i]['malicious_count']) + ' AV engine(s).' + os.linesep

            if malicious_flag:
                results += '*** MALWARE DETECTED. DO NOT CLICK THIS LINK ***'
            results += '```'

            await message.channel.send(results)

client.run(TOKEN)