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
EXP_BASE = os.getenv('EXP_BASE')
VT_KEY = os.getenv('VT_KEY')
VT_URL = os.getenv('VT_URL')
VT_ID_BASE = os.getenv('VT_ID_BASE')

headers = {"x-apikey" : VT_KEY}

client = discord.Client()


import re 
  
def FindURL(string): 
    # findall() has been used  
    # with valid conditions for urls in string 
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex,string)       
    return [x[0] for x in url] 

def expand(url):
    encoded_url = urllib.parse.quote(url)
    exp_response = requests.get(EXP_BASE + encoded_url)
    if exp_response.status_code == requests.codes.ok:
        exp_url = exp_response.content.decode('utf-8')
        return exp_url
    else:
        return None
     
def vt_check(exp_url):
    vt_id = requests.post(VT_URL, data=exp_url, headers=headers)
    vt_response = requests.get(VT_ID_BASE + str(vt_id), headers=headers)
                
    if vt_response.status_code != requests.codes.ok:
        return None
    else:
        return vt_response


@client.event
async def on_ready():
    print(f'{client.user} has connected to Discord!')

@client.event
async def on_message(message):
    if message.author == client.user:
        return
    if 'https://' not in message.content and 'http://' not in message.content:
        return
    elif 'https://bit.ly' not in message.content and 'https://t.co' not in message.content and 'https://goo.gl' not in message.content and 'https://ow.ly' not in message.content and 'https://tinyurl' not in message.content and 'https://buff.ly' not in message.content and 'https://bit.do' not in message.content and 'https://polr' not in message.content:
        return
    else:
        urls = FindURL(message.content)
        for url in urls:
            expanded_url = expand(url)
            if expanded_url is None:
                await message.channel.send('Could not expand url')
            else: 
                await message.channel.send('Expanded URL: `' + expanded_url + "`")

                # VT Analysis
                vt_response = vt_check(expanded_url)
                if vt_response is None:
                    await message.channel.send('VirusTotal Analysis: Expanded URL not found in VT database. Nonetheless, treat with caution.')
                else:
                    await message.channel.send('VirusTotal Analysis: ' + str(vt_response))


client.run(TOKEN)