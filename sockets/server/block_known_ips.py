
import requests
import json
from datetime import datetime
import os
import paramiko

currenMonth = datetime.now().month
currentYear = datetime.now().year
print(type(currenMonth))

def get_remote_stdout_sudo(cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.144.133', username='cristiana', password=os.environ.get('servicepassword'))
   
    stdin_raw, stdout_raw, stderr_raw = client.exec_command(cmd,get_pty = True)
    
    stdin_raw.write(os.environ.get('servicepassword')+ '\n')
    stdin_raw.flush()
    stdout_raw.channel.recv_exit_status() 

    stdout = []
    for line in stdout_raw: stdout.append(line.strip())
    stderr=[]
    for line in stderr_raw: stderr.append(line.strip())
    client.close()
    del client, stdin_raw, stdout_raw, stderr_raw
    return stdout,stderr

url='https://api.abuseipdb.com/api/v2/blacklist'
headers={"Key":os.environ.get('API_KEY')}
params = {"confidenceMinimum": 90}

response = requests.get(url, params=params, headers=headers)


if response.status_code == 200:  
    result=json.loads(response.text)['data']
    for r in result:
        badIp=r['ipAddress']
        abuseScore=r['abuseConfidenceScore']
        lastReportedAtYear=r['lastReportedAt'].split('T')[0].split('-')[0]
        lastReportedAtMonth=r['lastReportedAt'].split('T')[0].split('-')[1]
        if int(lastReportedAtYear) == currentYear and int(lastReportedAtMonth) == currenMonth:
            to_check=f'"-A INPUT -s {badIp}/32 -j DROP"'
            res,stderr= get_remote_stdout_sudo(f'sudo iptables-save | grep -- {to_check}')
            if len(res)<=2 or res[2] != to_check[1:-1]:
                res,err=get_remote_stdout_sudo(f'sudo iptables -A INPUT -s {badIp} -j DROP;')
            
