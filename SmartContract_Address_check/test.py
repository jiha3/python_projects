import web3 # should handle this problem
from web3 import Web3
import pandas as pd
import os
import requests
import sys

provider_url = 'https://eth.llamarpc.com' # Any ethereum mainnet

def check_address(i, item):
    try:
      res = requests.get(item, headers= headers)
      #print(res.status_code)
      if res.status_code != 200:
        print("interviewee %d no valid address" %(i+1))

      _address = "0x"+item.split('0x')[1]
      _address = Web3.to_checksum_address(_address)
      if len(_address) != 42:
          print("interviewee %d Contract address length is not 20 bytes"%(i+1))
          return
      code = bytes(w3.eth.get_code(_address))
      
      if(len(code)>0):
        print("interviewee %d valid"% (i+1))
      else:
        print("interviewee %d , not a contract but a wallet address"%(i+1))
    except:
       print("interviewee %d no valid address"%(i+1))
       return

if __name__=="__main__":
  headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
  test_file = os.getcwd()+"/test_file.csv"
  w3 = Web3(Web3.HTTPProvider(provider_url))
  if not w3.is_connected():
     print("Problem with connecting to ethereuem mainnet")
     sys.exit(1)
  df = pd.read_csv(test_file)
  addresses = df['Address']
  for i, item in enumerate(addresses):
    check_address(i, item)
  