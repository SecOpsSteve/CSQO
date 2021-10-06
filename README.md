# CrowdStrike Queued Operations

## Introduction
Interact with CrowdStrike API's to run or queue Real Time Response scripts or actions on multiple hosts, even those that are offline. Offline hosts will execute the queued action when they next check-in. Sessions live for 7 days.

## Features
1. Run an RTR script.
1. Apply Sensor Tags to the Windows Registry.
1. Make a registry change. (Danger Zone)

## Dependencies
* CrowdStrike Falcon.
* API key and secret, with appropriate permissions.
* Some RTR scripts.
* Somewhere to run python3.

## Directions
1. `git clone https://github.com/SecOpsSteve/CSQO.git`
1. `cd CSQO`
1. Produce a list of hosts (new line delimited).
1. The API ClientID and Secret is read in from the environment. Set them with;
    1. `export csID="<api_clientID>"`
    1. `export csSecret="<api_secret>"`
1. `python3 CSQO.py`
1. Follow the simple menu.
1. `ctrl c` to exit at any time.

```

                               /| /|         
                              / |/ | .-~/    
                          |\ |  |  |/  /  _  
         /|               | \|  |  |  /.-~/  
        | \   /\       |\ |  |  |  |  \  /   
 __  | \|   \|  \ \ __/  \   \   `  _. |    
 \ ~-\  `\   `\  \  \ ~\  \   `. .-~   |    
  \   ~-. "-.  `  \  ^._ ^. "-.  /  \   |    
.--~-._  ~-  `  _  ~-_.-"-." ._ /._ ." ./    
 >--.  ~-.   ._  ~>-"    "\   /   /   ]     
^.___~"--._    ~-{  .-~ .  `\ \ . /    |     
 <__ ~"-.  ~       /_/   \   \  /   : |    
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


 CrowdStrike Queued Operations

 "a" > Run an RTR script.
 "b" > Apply sensor tags.
 "c" > Apply registry change. (Danger Zone)
 "s" > Specify alternate API secrets.
 "q" > Quit.

 Select an option: 
```
