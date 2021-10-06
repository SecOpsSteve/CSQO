#!/usr/bin/env python3

import os
import requests
from datetime import datetime, timedelta
import json

clientID = os.environ.get('csID')
clientSecret = os.environ.get('csSecret')

# Make a call to receive a Bearer token
def getBearer(clientID, clientSecret): 
    URL = "https://api.crowdstrike.com/oauth2/token"
    headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/x-www-form-urlencoded'
    }
    payload={
        'client_id': clientID,
        'client_secret': clientSecret
    }
    response = requests.request("POST", URL, headers=headers, data=payload)
    bearerToken = json.loads(response.text)['access_token']
    return bearerToken

# Resolve a list of hostnames into a list of crowdstrike host IDs
def getHostIDs(token, hostnames):
    lastSeen = (datetime.now() - timedelta(days=14)).strftime('%Y-%m-%d')
    hostList = ""
    if len(hostnames)>1:
        hostList = hostList + "hostname:'" + hostnames[0] + "'"
        for host in hostnames[1:]:
            hostList = hostList + ", hostname:'" + host + "'" #listofhosts like hostname:'5CG9471W56', hostname:'5CG9237FC2'
    else:
        hostList = hostList + "hostname:'" + hostnames[0] + "'"
    filter = "filter=(last_seen:>'"+ lastSeen +"')%2B("+hostList+")"
    URL = "https://api.crowdstrike.com/devices/queries/devices/v1?" + filter
    payload={}
    headers = {
    'Accept': 'application/json',
    'Authorization': 'bearer ' + token
    }
    response = requests.request("GET", URL, headers=headers, data=payload)
    hostIDs = json.loads(response.text)['resources']
    return hostIDs

# Create a batch session with offline queueing for given hosts IDs
def newSession(token, hostIDList):
    URL = "https://api.crowdstrike.com/real-time-response/combined/batch-init-session/v1"  
    headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': 'bearer ' + token
    }
    payload={
        "host_ids": hostIDList,
        "queue_offline": "true"
    }
    # unfortunately the API balks when you send it with boolean value quoted. This removes the quotes before making call. Error it gives is unable to read JSON body.
    formatted = json.dumps(payload).replace("\"true\"","true")
    response = requests.request("POST", URL, headers=headers, data=formatted)
    batchSessionID = json.loads(response.text)['batch_id']
    return batchSessionID

# Schedule RTR Active Responder task to run a given script on given batch session
def scheduleRTRScript(token, batchID, script):
    URL = "https://api.crowdstrike.com/real-time-response/combined/batch-active-responder-command/v1"
    headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': 'bearer ' + token
    }
    payload={
        "base_command": "runscript",
        "batch_id": batchID,
        "command_string": "runscript -CloudFile='"+ script +"' -CommandLine=''"
    }
    response = requests.request("POST", URL, headers=headers, data=json.dumps(payload))
    if len(json.loads(response.text)['errors']) == 0:
        print("Successfully scheduled script for batchID: " + batchID)
    else:
        print(json.loads(response.text))

# Change the registry value on 1 or more hosts. Requires a registry subkey to set.
def scheduleRegSet(token, batchID, regKey, regValueType, regValue):
    URL = "https://api.crowdstrike.com/real-time-response/combined/batch-active-responder-command/v1"
    headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': 'bearer ' + token
    }
    payload={
        "base_command": "reg",
        "batch_id": batchID,
        "command_string": "reg set " + regKey + " -ValueType=" + regValueType + " -Value=" + regValue
    }
    response = requests.request("POST", URL, headers=headers, data=json.dumps(payload))
    if len(json.loads(response.text)['errors']) == 0:
        print("Successfully scheduled registry change for batchID: " + batchID)
    else:
        print(json.loads(response.text))

# Apply Crowdstrike tags to a host or list of hosts.
def scheduleSetTags(token, batchID, tags):
    URL = "https://api.crowdstrike.com/real-time-response/combined/batch-active-responder-command/v1"
    headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': 'bearer ' + token
    }
    payload={
        "base_command": "reg",
        "batch_id": batchID,
        "command_string": "reg set HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default GroupingTags -ValueType=REG_SZ -Value="+ tags
    }
    response = requests.request("POST", URL, headers=headers, data=json.dumps(payload))
    if len(json.loads(response.text)['errors']) == 0:
        print("Successfully scheduled tag update for batchID: " + batchID)
    else:
        print(json.loads(response.text))

# targetLoader function will prompt for and read in a file to a set and return a unique list.
def targetLoader():
    targets = (input("\nProvide the list of hosts, enter filename (targets.txt): ") or "targets.txt")
    while not (os.path.isfile(targets)):
        print(f" File not found: {targets}")
        targets = (input("\nProvide the list of hosts, enter filename (targets.txt): ") or "targets.txt")
    print(f" Reading \"{targets}\"..")
    with open(targets) as f:
        targetList = f.read().splitlines()
    uniqueTargets = list({x.upper() for x in targetList})
    print(f"\nThe following list will be used:\n{uniqueTargets}")
    print(f"\n\"{targets}\" contains {len(targetList)} item(s) ({len(uniqueTargets)} unique).")
    return uniqueTargets

### Main ###

falconbanner = """

                               /| /|         
                              / |/ | .-~/    
                          |\ |  |  |/  /  _  
         /|               | \|  |  |  /.-~/  
        | \   /\       |\ |  |  |  |  \  /   
 __  | \|   \|  \\ \ __|  \   \   `  _. |    
 \ ~-\  `\   `\  \  \\ ~\  \   `. .-~   |    
  \   ~-. "-.  `  \  ^._ ^. "-.  /  \   |    
.--~-._  ~-  `  _  ~-_.-"-." ._ /._ ." ./    
 >--.  ~-.   ._  ~>-"    "\\   /   /   ]     
^.___~"--._    ~-{  .-~ .  `\ \ . /    |     
 <__ ~"-.  ~       /_/   \   \\  /   : |    
   ^-.__           ~(_/   \   >._:   | l______     
       ^--.,___.-~"  /_/   !  `-.~"--l_ /     ~"-.  
              (_/ .  ~(   /'     "~"--,Y    -=O. _) 
               (_/ .  \  :           / l       ~~o \ 
                \ /    `.    .     .^   \_.-~"~--.  ) 
                 (_/ .   `  /     /       !       )/  
                  / / _.   '.   .':      /        '  
                  ~(_/ .   /    _  `  .-<_      
                    /_/ . ' .-~" `.  / \  \          ,==- 
                    ~( /   '  :   | /   "-.~-.______// 
                      "-,.    |   |/ \_    __{--->._(==- 
                       //(     \  <    ~"~"     // 
                      /' /\     \  \     ,==-  (( 
                    .^. / /\     "  }__ //===-   
                   / / ' '  "-.,__ {---(==- 
                 .^ '       :  |  ~"   // 
                / .  .  . : | :!      (( 
               (_/  /   | | j-"         
                 ~-<_(_.^-~"               
"""
menutext = """
 CrowdStrike Queued Operations

 \"a\" > Run an RTR script.
 \"b\" > Apply sensor tags.
 \"c\" > Apply registry change. (Danger Zone)
 \"s\" > Specify API secrets.
 \"q\" > Quit.
"""
print(falconbanner)

while True:
    print(f"{menutext}")
    option = input(" Select an option: ").lower()
    if option == "a":
        print("\nYou chose to run an RTR script.")
        scriptName = input("Enter the RTR script name: ")
        hostnames = targetLoader()
        # Prompt to proceed?..
        if (input("\nAre you sure you want to proceed? (y/N): ") or "N").lower() == "y":
            print("Proceeding..")
        
            print("Asking nicely for a bearer token...")
            token = getBearer(clientID, clientSecret)
            print("Taking the list of hostnames and retrieving the hostIDs...")
            hostIDList = getHostIDs(token, hostnames)
            print("Creating an offline session...")
            batchID = newSession(token, hostIDList)
            print(f"Dotting the i's and crossing the t's to run your script: \"{scriptName}\"")
            scheduleRTRScript(token, batchID, scriptName)
        else:
            print("[!] Not proceeding.")

    elif option == "b":
        print("\nYou chose to apply sensor tags.")
        tags = input("\nEnter the desired tag(s), e.g. \"TEST,INFOSEC\": ")
        hostnames = targetLoader()
        if (input("\nAre you sure you want to proceed? (y/N): ") or "N").lower() == "y":
            print("Proceeding..")

            print("Asking nicely for a bearer token...")
            token = getBearer(clientID, clientSecret)
            print("Taking the list of hostnames and retrieving the hostIDs...")
            hostIDList = getHostIDs(token, hostnames)
            print("Creating an offline session...")
            batchID = newSession(token, hostIDList)
            print("Applying Tags to batchID: " + batchID)
            scheduleSetTags(token, batchID, tags)
        else:
            print("[!] Not proceeding.")

    elif option == "c":
        print("\nYou chose to apply a registry change.")
        print("Danger Zone")
        regKey = (input("Enter registry key: ") or "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default GroupingTags")
        regValueType = (input("Enter registry value type: ") or "REG_SZ")
        regValue = (input("Enter registry value: ") or "TEMP")
        hostnames = targetLoader()
        print(f"\nRTR registry command:\n \"reg set {regKey} -ValueType={regValueType} -Value={regValue}\"")

        if (input("\nAre you sure you want to proceed? (y/N): ") or "N").lower() == "y":
            print("Proceeding..")

            print("Asking nicely for a bearer token...")
            token = getBearer(clientID, clientSecret)
            print("Taking the list of hostnames and retrieving the hostIDs...")
            hostIDList = getHostIDs(token, hostnames)
            print("Creating an offline session...")
            batchID = newSession(token, hostIDList)
            print("Applying registry changes to batchID: " + batchID)
            scheduleRegSet(token, batchID, regKey, regValueType, regValue)
        else:
            print("[!] Not proceeding.")
        
    elif option == "s":
        print(f"\n You chose to update the clientID and ClientSecret.")
        clientID = input(" Enter API ClientID: ")
        clientSecret = input(" Enter API ClientSecret: ")
        print(f"\n clientID = {clientID}\n clientSecret = {clientSecret}")

    elif option == "q":
        print(f"\n You chose to quit.")
        break
    else:
        print(f"\n Invalid option, \"{option}\" does not exist!")
