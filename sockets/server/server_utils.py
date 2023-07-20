import numpy as np
import subprocess
import re
import glob
import os 
import pandas as pd
from itertools import groupby
from operator import itemgetter
http_log_file='/home/cristiana/pyqt/two_windows/logs/http.log'
conn_log_file='/home/cristiana/pyqt/two_windows/logs/conn.log'
file_log_file='/home/cristiana/pyqt/two_windows/logs/files.log'

# file_features=['mime_type','duration','total_bytes','seen_bytes','orig_h']
file_features=['mime_type','duration','seen_bytes','orig_h','total_bytes']
conn_features=['service','duration', 'proto', 'resp_p','conn_state','orig_pkts','orig_h']
http_features = ['method','resp_p', 'resp_mime_types', 'orig_mime_types','orig_h','request_body_len','response_body_len']
import math
import csv 
import json 

def csv_to_json(path):
    output=subprocess.call('/home/cristiana/pyqt/two_windows/logs/parse_before.sh',shell=True)
    onlyfiles = [os.path.join(path, f) for f in os.listdir(path) if os.path.isfile(os.path.join(path, f)) and f.endswith('.log')]
    for file in onlyfiles:
        try:
            jsonArray = []
            with open(file, encoding='utf-8') as csvf: 
                csvReader = csv.DictReader(csvf,delimiter='\t') 
                for row in csvReader: 
                    jsonArray.append(row)
            with open(file, 'w', encoding='utf-8') as jsonf: 
                jsonString = json.dumps(jsonArray, indent=4)
                jsonf.write(jsonString)
        except:
            pass
# Extract IPv4 from a string
def get_ips(string):
    ipv4_extract_pattern = "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    return re.findall(ipv4_extract_pattern, string)


def jitter(arr):
    stdev = .02*(max(arr)-min(arr))
    return arr + np.random.randn(len(arr)) * stdev

def warn(*args, **kwargs):
    pass

def clean_df(df):
    df=df.dropna()
    df=df.applymap(str)
    return df
def create_df_file(file):
    with open(file,'r') as f:
        bro_df=pd.DataFrame( json.load(f))
    bro_df=clean_df(bro_df)
    bro_df.rename(columns = {'id.orig_h':'orig_h'}, inplace = True)
    bro_df['duration'] = bro_df['duration'].fillna('0')
    bro_df['duration']=bro_df['duration'].astype(float).apply(lambda x: str(math.floor(x)))
    
    return bro_df,file_features
def create_df_conn(file):
    with open(file,'r') as f:
        bro_df=pd.DataFrame( json.load(f))
    bro_df=clean_df(bro_df)
    bro_df.rename(columns = {'id.resp_p':'resp_p','id.orig_h':'orig_h'}, inplace = True)
    bro_df['duration'] = bro_df['duration'].replace('-','0')
    print(bro_df['duration'])
    bro_df['duration']=bro_df['duration'].astype(float).apply(lambda x: str(math.floor(x)))
    return bro_df,conn_features
def create_df_http(file):
    with open(file,'r') as f:
        bro_df=pd.DataFrame( json.load(f))
    bro_df=clean_df(bro_df)
    bro_df.rename(columns = {'id.resp_p':'resp_p','id.orig_h':'orig_h'}, inplace = True)
    return bro_df,http_features

from datetime import datetime
def get_alert_timestamp(date_string):
    current_year = datetime.now().year
    full_date_string = f"{current_year}/{date_string}"
    datetime_obj = datetime.strptime(full_date_string, "%Y/%m/%d-%H:%M:%S.%f")
    timestamp = str(datetime_obj.timestamp())
    timestamp=timestamp.split('.')[0]
    return timestamp


def add_new_firewall_rule(badIp):   
    to_check=f'"-A INPUT -s {badIp}/32 -j DROP"'
    res,err= get_remote_stdout_sudo(f'sudo iptables-save | grep -- {to_check}')
    if len(res)<=2 or res[2] != to_check[1:-1]:
        res,err=get_remote_stdout_sudo(f'sudo iptables -A INPUT -s {badIp} -j DROP;')
    return res,err

import vt
import os
from base64 import b64decode
from time import sleep


client = vt.Client(os.environ.get('vtapikey'))
def check_files_with_vt(path,command,ip):

    #daca alt thread nu a terminat
    # while any(os.path.isfile(os.path.join(path, item)) for item in os.listdir(path)):
    #     sleep(1)
   
    output=subprocess.run(command[0],shell=True,stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    output=subprocess.run(command[1],shell=True,stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    for file in os.listdir(path):
        file=os.path.join(path,file)
        if os.path.isfile(file):
            with open(file, "rb") as f:
                print(f'Scanning file {file}')
                content=f.read()
                if b'MZ' in content:
                    print("here")
                    analysis = client.scan_file(f,wait_for_completion=True)
                    analysis_results = client.get_object("/analyses/{}".format(analysis.id))                                                                                                                                                                                                                       
                    id=b64decode(analysis.id ).decode().split(':')[0]
                    obj=client.get_object(f"/files/{id}")
                    print(obj.last_analysis_stats)
                    if obj.last_analysis_stats['malicious'] > 0 or obj.last_analysis_stats['suspicious'] > 0:
                        print(f'Search completed!!\n File {file} appers o be malicious!')
                        # add_new_firewall_rule(ip)
                        for x in os.listdir(path):
                            x=os.path.join(path,x)
                            if os.path.isfile(x): os.remove(x)
                        return
                    else:
                        print(f'Search completed!!\n File {file} is safe!')
                    os.remove(file)
                else:
                    os.remove(file)
        
def search_for_malicious_file(ip,timestamp):
    res,err=get_remote_stdout_sudo('sudo bash /home/cristiana/communicate.sh')
    # print(res,err)
    path='/home/cristiana/capfiles'
 
    timestamp_before=int(timestamp) - 120
    timestamp_after=int(timestamp) + 120
    command =[f'tshark -r {path}/capfile -Y "(frame.time_epoch >= {timestamp_before}) && (frame.time_epoch <= {timestamp_after}) && ip.src=={ip}" -w {path}/extracted.pcap  -t ad  2>/dev/null',f'tshark -r {path}/extracted.pcap --export-objects "http,{path}/extracted/" -t ad 2>/dev/null && rm {path}/extracted.pcap']

    path=f'{path}/extracted'
    import threading
    thread=threading.Thread(target=check_files_with_vt,args=(path,command,ip))
    thread.start()

    
#serverul aduna toate log-urile 
#din capturile aferente de trafic, general fiserele de log, pe care zeek le pune default in folderul curent asa ca le mutam in folderul de logs
#la nevoie, functia poate fi reapelata
def get_zeek_logs():
    try:
        #output=subprocess.check_output(['zeek','-C','-r','/home/cristiana/capfiles/capfile'])
        res,err=get_remote_stdout_sudo('sudo bash /home/cristiana/communicate.sh')

        # print(res,err)
        command='tcpdump -r /home/cristiana/capfiles/capfile -w /home/cristiana/capfiles/fixed'
        output=subprocess.run(command,shell=True,stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        command='zeek -C -r /home/cristiana/capfiles/fixed'
        output=subprocess.run(command,shell=True,stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(e.output)
    output=subprocess.call('mv /home/cristiana/pyqt/two_windows/sockets/server/*.log /home/cristiana/pyqt/two_windows/logs/',shell=True)
    csv_to_json('/home/cristiana/pyqt/two_windows/logs/')

def get_local_zeek_logs(dest_host,timestamp,file):
    subprocess.run('bash /home/cristiana/pyqt/two_windows/sockets/server/parse_zeek_logs.sh',shell=True)
    path=f'/home/cristiana/pyqt/two_windows/logs/current/{file}'

    with open(path,'r') as f:
        reader=csv.DictReader(f,delimiter='\t') 
        data = [row for row in reader]
        for d in data:
            d['ts']=d['ts'].split('.')[0]
    
        #grupam dupa ip-ul si portul sursei care realizeaza nmap
        data3 = sorted(data,key = itemgetter('ts','id.orig_h','id.orig_p','id.resp_h'))        
        investigation_alerts=groupby(data3,key = itemgetter('ts','id.orig_h','id.resp_p','id.resp_h'))
        
        for key, group in investigation_alerts:
            if key[1] != key[3]:
                timestamp=int(timestamp)
                compare_key=int(key[0])
                if key[3]==dest_host and (compare_key>timestamp-100 and compare_key<timestamp+100):
                    return key


from sklearn.metrics import silhouette_score
from sklearn.cluster import KMeans

#se apeleaza cu bro_matrix
def detect_optimal_number_of_clusters(feature_matrix):
    #silhouette scoring este o măsură a cât de asemănător este un obiect cu propriul său cluster în comparație cu alte clustere (separare). Silueta variază de la -1 la 1, unde o valoare mare indică faptul că obiectul este bine potrivit cu acesta. propriul cluster și prost potrivit cu clusterele învecinate. Dacă majoritatea obiectelor au o valoare mare, atunci configurația de clustering este adecvată. Dacă multe puncte au o valoare scăzută sau negativă, atunci configurația clustering poate avea prea multe sau prea puține clustere.
    #testam valoarea scorului pana cand ne este indeicat numarul optim de clustere din grafic, apoi introducem in interfata parametrii pe care ii dam algoritmului
    scores = []
    clusters = range(2,10)
    feature_matrix_aux=feature_matrix.copy()
    for K in clusters:
        clusterer = KMeans(n_clusters=K)
        try:
            cluster_labels = clusterer.fit_predict(feature_matrix_aux)
            score = silhouette_score(feature_matrix_aux, cluster_labels)
            scores.append(score)
        except Exception as e:
            print("Stopping here ",e)
            break
    return scores


from zat.dataframe_to_matrix import DataFrameToMatrix
to_matrix = DataFrameToMatrix()
from sklearn.decomposition import PCA
from sklearn.cluster import AgglomerativeClustering

def get_cluster_groups(df,ftrs,clf,bro_matrix,numClusters,pcaComponents,clustering_alg):
    df['score']=clf.decision_function(bro_matrix)
    
    odd_df=df[ftrs][clf.predict(bro_matrix) == -1] #y=-1 abnormal y=1 normal
    
    odd_matrix = to_matrix.fit_transform(odd_df)
   
    if clustering_alg=='kmeans':
        clustering = KMeans(n_clusters=numClusters).fit_predict(odd_matrix)  
    else: 
        clustering = AgglomerativeClustering(n_clusters=numClusters).fit_predict(odd_matrix)
    pca= PCA(n_components=pcaComponents).fit_transform(odd_matrix)
    
    
    odd_df['x'] = pca[:, 0] 
    odd_df['y'] = pca[:, 1] 
    odd_df['cluster'] = clustering
    #jitter este folosit pentru a putea proiecta in 2D PCA in oricate dimensiuni
    odd_df['jx'] = jitter(odd_df['x'])
    odd_df['jy'] = jitter(odd_df['y'])
    #avem n_clusters liste de dictiona
    
    cluster_groups = odd_df.groupby('cluster')
    result=dict()
    for key, group in cluster_groups:
        res=group.to_json(orient='records')#string representation    
        result[str(key)]=res
    
    result=json.dumps(result)
    return result


import ssl
import socket
import paramiko

def str_to_dict(string):
    string = string.strip('{}')
    pairs = string.split('; ')
    return {key: value for key, value in (pair.split(':') for pair in pairs if ':' in pair) }


def get_remote_stdout(cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    client.connect('192.168.144.133', username='cristiana', password=os.environ.get('servicepassword'))

    stdin_raw, stdout_raw, stderr_raw = client.exec_command(cmd)
    stdout_raw.channel.recv_exit_status() 

    stdout = []
    for line in stdout_raw: stdout.append(line.strip())
    stderr=[]
    for line in stderr_raw: stderr.append(line.strip())
    client.close()
    del client, stdin_raw, stdout_raw, stderr_raw
    return stdout,stderr

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

def parse_rule_file():
    rule_file='/etc/snort/rules/local.rules'
    data=[]

    rules,err=get_remote_stdout(f'cat {rule_file}')
    
    for i,rule in enumerate(rules):
        action=rule.split(' ')[0]
        if "#" not in action:
           
            proto=rule.split(' ')[1]
            source_net= rule.split(' ')[2]
            source_port=rule.split(' ')[3]
            dest_net=rule.split(' ')[5]
            dest_port=rule.split(' ')[6]
            message='{'+"action:"+action+"; proto:"+proto+"; source_net:"+source_net+"; source_port:"+source_port+"; dest_net:"+dest_net+"; dest_port:"+dest_port+"; " +rule.split('(')[1].split(')')[0][:-1]+'}'
            message=message.replace('msg','Rule')
            
            try:
                data.append(str_to_dict(message))
            except: pass

    return data
    
def parse_alert_file():
    data=[]
    keys=["@timestamp","Alert","protocol","source","destination"]
  
    alerts,err=get_remote_stdout("cat /var/log/snort/alert")
    
    for alert in alerts:
        try:
            alert_dict={}
            alert_dict[keys[0]]=alert.split('[**] ')[0].strip()
            alert_dict[keys[1]]=alert.split('[**]')[1].split(']')[1].strip()
            alert_dict[keys[2]]=alert.split('{')[1].split('}')[0]
            alert_dict[keys[3]]=alert.split(' ')[-3]
            alert_dict[keys[4]]=alert.split(' ')[-1]
            data.append(alert_dict)
        except:
            print(alert)
    
    return data

def init():
    get_zeek_logs()

init()