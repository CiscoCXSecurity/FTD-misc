import json,sys,openpyxl,requests,getpass,os,time,code,ast,pprint
requests.packages.urllib3.disable_warnings()
headers = {}

def connect():
    global headers
    global server,username,password,auth_url,tokentimer
    serverIP = input("Server IP Adress:  ")
    server = ("https://%s" % serverIP)
    username = input("Username: ")
    password = input("Password: ")
    r = None
    headers = {'Content-Type': 'application/json'}
    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = server + api_auth_path
    r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
    auth_headers = r.headers
    auth_token = auth_headers.get('X-auth-access-token', default=None)
    if auth_token == None:
        print("Connection Failed")
        return
    headers['X-auth-access-token']=auth_token
    tokentimer = time.time()
    print("Connected")
    print("         ")
    print("Loading IPS Policies")
    global ips
    ips = {}
    ips_path = ("/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/intrusionpolicies?limit=1000")
    url = server + ips_path
    r = requests.get(url,headers = headers, verify = False)
    ips_resp = json.loads(r.text)
    for i in range(0,len(ips_resp['items'])):
        ips_name = ips_resp["items"][i]["name"]
        ips[ips_name] = ips_resp["items"][i]
        ips[ips_name].pop('links',None)

    print("IPS Policies Loaded")
    print("         ")
    print("Loading Variable Sets")
    global varset
    varset = {}
    varset_path = ("/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/variablesets?limit=1000")
    url = server + varset_path
    r = requests.get(url,headers = headers, verify = False)
    varset_resp = json.loads(r.text)
    for i in range(0,len(varset_resp['items'])):
        varset_name = varset_resp["items"][i]["name"]
        varset[varset_name] = varset_resp["items"][i]
        varset[varset_name].pop('links',None)

    print("Variable Sets Loaded")
    print("         ")
    print("Loading File Policies")
    global filepol
    filepol = {}
    filepol_path = ("/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/filepolicies?limit=1000")
    url = server + filepol_path
    r = requests.get(url,headers = headers, verify = False)
    filepol_resp = json.loads(r.text)
    for i in range(0,len(filepol_resp['items'])):
        filepol_name = filepol_resp["items"][i]["name"]
        filepol[filepol_name] = filepol_resp["items"][i]
        filepol[filepol_name].pop('links',None)

    print("File Policies Loaded")
    print("         ")   
    print("Loading Syslog Servers")
    global syslog
    syslog = {}
    syslog_path = ("/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/syslogalerts?limit=1000")
    url = server + syslog_path
    r = requests.get(url,headers = headers, verify = False)
    syslog_resp = json.loads(r.text)
    for i in range(0,len(syslog_resp['items'])):
        syslog_name = syslog_resp["items"][i]["name"]
        syslog[syslog_name] = syslog_resp["items"][i]
        syslog[syslog_name].pop('links',None)
    print("Syslog Servers Loaded")
    

def configrules():
    ips.update({"None":{"name":"None"}})
    filepol.update({"None":{"name":"None"}})
    syslog.update({"None":{"name":"None"}})
    global setips, ips_setting, varset_setting
    setips = input("Update IPS policy for all existing rules? Y/N: ")
    if setips == "y" or setips == "Y":
        name_check=[]
        print("Available Policies:")
        print(" ")
        for ips_pol in ips:
            print(ips[ips_pol]['name'])
            name_check.append(ips[ips_pol]['name'])
            print(" ")
        ips_setting = input("Enter the name of the IPS policy that will be used in all rules: ")
        if ips_setting not in name_check:
            setips = "N"
            print("Policy name invalid. Exiting")
            return
    else:
        setips = "n"
        
    if (setips == "y" or setips == "Y"):
        if (ips_setting != "None"):
            name_check=[]
            print("Enter the variable set to be used with the IPS Policy:")
            print(" ")
            for varsetname in varset:
                print(varset[varsetname]['name'])
                name_check.append(varset[varsetname]['name'])
                print(" ")
            varset_setting = input("Enter the name of the variable set that will be used in all rules: ")
            if varset_setting not in name_check:
                setips = "N"
                print("Variable set name invalid. Exiting")
                setips = "n"
                return
                

    global setfilepol,filepol_setting
    setfilepol = input("Update AMP policy for existing rules? Y/N: ")
    if setfilepol == "y" or setips == "Y":
        name_check=[]
        print("Available Policies:")
        print(" ")
        for filepol_pol in filepol:
            print(filepol[filepol_pol]['name'])
            name_check.append(filepol[filepol_pol]['name'])
            print(" ")
        filepol_setting = input("Enter the name of the AMP policy that will be used in all rules: ")
        if filepol_setting not in name_check:
            setfilepol = "N"
            print("Policy name invalid. Exiting")
            return
    else:
        setfilepol = "n"

    global setlogb,setloge,setsyslog,setlogfmc,syslog_setting,logb_setting,loge_setting,setlogfmc_setting
    setlogb = input("Update Log at beginning of connection for all rules? Y/N: ")
    if setlogb.lower() == "y":
        logb_setting = input("Log at beginning of connection? Y/N: ")
    setloge = input("Update Log at end of connection? Y/N: ")
    if setloge.lower() == "y":
        loge_setting = input("Log at end of connection? Y/N: ")
    setlogfmc = input("Update Send logs to FMC? Y/N: ")
    if setlogfmc.lower() == "y":
        setlogfmc_setting = input("Send logs to FMC? Y/N: ")
    setsyslog = input("Update Send logs to syslog server? Y/N: ")
    if setsyslog == "y" or setsyslog == "Y":
        name_check=[]
        print("Available Syslog Servers:")
        print(" ")
        for syslog_servers in syslog:
            print(syslog[syslog_servers]['name'])
            name_check.append(syslog[syslog_servers]['name'])
            print(" ")
        syslog_setting = input("Enter the name of the Syslog server that will be used in all policies: ")
        if syslog_setting not in name_check:
            setsyslog = "N"
            print("Syslog server name invalid. Exiting")
            return
    else:
        setsyslog = "n"
        
    ips["None"]={}
    filepol["None"]={}
    syslog["None"]={}

def updatepolicy():
    global headers, server,pol,rules,tokentimer,username,password,auth_url
    rules = {}
    offset = 0
    if headers == {}:
        print("FMC not connected")
        return
    api_path = ("/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies")
    url = server + api_path
    r = requests.get(url, headers=headers, verify=False)
    resp = json.loads(r.text)
    print('Available Policies:')
    for i in range(0,len(resp['items'])):
        print('policy name:',resp['items'][i]['name'],"  Object ID:",resp['items'][i]['id'])
    pol = input('Copy and paste the Object ID for the Policy you want to update:')
    url_pol = (url + "/" + pol + "/accessrules?limit=1000")
    r = requests.get(url_pol,headers=headers,verify=False)
    resp = json.loads(r.text)
    resp2 = resp
    filepolvalidapps = ['HTTP','POP3','SMTP','HTTPS','IMAP','FTP','NetBIOS-ssn (SMB)']
    while "next" in resp2['paging']:
        offset = offset + 1000
        url_pol = (url + "/" + pol + "/accessrules?limit=1000&offset=%d" % (offset))
        r2 = requests.get(url_pol,headers=headers,verify=False)
        resp2 = json.loads(r2.text)
        resp['items'] = resp['items'] + resp2['items']
    j = 0
    for rulenum2 in range(0,len(resp['items'])):
        if time.time() - tokentimer > 1700:
            headers.pop('X-auth-access-token',None)
            r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
            auth_headers = r.headers
            auth_token = auth_headers.get('X-auth-access-token', default=None)
            tokentimer = time.time()
            headers['X-auth-access-token']=auth_token
            print('new token created')
        filepolok = 0
        indrulelink = resp['items'][rulenum2]['links']['self']
        r = requests.get(indrulelink,headers=headers,verify=False)
        ruleup = json.loads(r.text)
        ruleup.pop('metadata',None)
        ruleup.pop('links',None)
        #code.interact(local=dict(globals(),**locals()))
        if setips == "y" or setips == "Y":
           ruleup.update({'ipsPolicy': ips[ips_setting]})
           if ips_setting != 'None':
               ruleup.update({'variableSet': varset[varset_setting]})
           

        if setfilepol == "y" or setfilepol == "Y":
            #if 'applications' not in ruleup:
            #    ruleup.update({'filePolicy': filepol[filepol_setting]})
            #if 'applications' in ruleup:
            #    ruleapplist = []
            #    for i in range(0,len(ruleup['applications']['applications'])):
            #        ruleapplist.append(ruleup['applications']['applications'][i]['name'])
            #    for apps in ruleapplist:
            #        if apps in filepolvalidapps:
            #            filepolok = 1
            #if filepolok == 1:
            ruleup.update({'filePolicy': filepol[filepol_setting]})

        if setlogb.lower() == "y":
           if logb_setting.lower() == "y":
               ruleup.update({'logBegin': True})
           else:
                ruleup.update({'logBegin': False})
            
        if setloge.lower() == "y":
           if loge_setting.lower() == "y":
               ruleup.update({'logEnd': True})
           else:
                ruleup.update({'logEnd': False})

        if setlogfmc.lower() == "y":
           if loge_setting.lower() == "y":
               ruleup.update({'sendEventsToFMC': True})
           else:
                ruleup.update({'sendEventsToFMC': False})

        if setsyslog == "y" or setsyslog == "Y":
            if syslog_setting != "None":
                ruleup.update({'syslogConfig': syslog[syslog_setting]})
            else:
                ruleup.pop('syslogConfig',None)
        put_data = json.dumps(ruleup)
        putresp = requests.put(indrulelink,headers=headers,data=put_data,verify=False)
        j = j +1
        if j > 115:
            print("Script paused for 1 minute due to max API calls per minute")
            time.sleep(60)
            print("Resuming")
            j = 0
        #code.interact(local=dict(globals(),**locals()))

print("Calling connect() function")		
connect()
print("Calling configrules() function")
configrules()
print("Calling updatepolicy() function")
updatepolicy()
print("SCRIPT COMPLETE")


