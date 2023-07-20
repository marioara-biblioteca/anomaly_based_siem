
def get_pca_metric(matrix):
    pca=PCA(n_components=65)
    #scaler = StandardScaler()
    #df_scaled = scaler.fit_transform(matrix)
    #pca.fit(df_scaled)
    pca.fit(bro_matrix)
    X_scaled=pca.transform(bro_matrix)
    cev = np.cumsum(pca.explained_variance_ratio_)
    tw = trustworthiness(bro_matrix,X_scaled)
    print("Trustworthiness:", round(tw, 3))
    plt.plot(range(1, len(cev) + 1), cev, marker='o')
    plt.xlabel('Number of PC')
    plt.ylabel('CEV')
    plt.title('CEV vs. Number of PC')
    plt.grid()
    plt.show()

def get_elbow_score():
    wcss = []
    for k in range(2, 11):
        kmeans = KMeans(n_clusters=k, random_state=0)
        kmeans.fit(odd_matrix)
        wcss.append(kmeans.inertia_)

    # Plot the elbow method
    plt.plot(range(2, 11), wcss, marker='o')
    plt.xlabel('Number of Clusters (k)')
    plt.ylabel('WCSS')
    plt.title('Elbow Method')
    plt.show()
from base64 import b64encode,b64decode
import pickle
import json 
import pandas as pd
from zat.dataframe_to_matrix import DataFrameToMatrix
to_matrix = DataFrameToMatrix()
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from time import sleep
import subprocess
import vt
import os
from base64 import b64decode


http_log_file='/home/cristiana/pyqt/two_windows/logs/http.log'
conn_log_file='/home/cristiana/pyqt/two_windows/logs/conn.log'
file_log_file='/home/cristiana/pyqt/two_windows/logs/files.log'

# file_features=['mime_type','duration','total_bytes','seen_bytes','orig_h']
file_features=['mime_type','duration','seen_bytes','orig_h','total_bytes']

conn_features=['service','duration', 'proto', 'resp_p','conn_state','orig_pkts','orig_h']
http_features = ['method','resp_p', 'resp_mime_types', 'orig_mime_types','orig_h','request_body_len','response_body_len']
import math
def clean_df(df):
    df=df.dropna()
    df=df.applymap(str)
    return df
def create_df_file(file):
    with open(file,'r') as f:
        bro_df=pd.DataFrame( json.load(f))
    bro_df=clean_df(bro_df)
    bro_df.rename(columns = {'id.orig_h':'orig_h'}, inplace = True)
    bro_df['duration']=bro_df['duration'].astype(float).apply(lambda x: str(math.floor(x)))
    
    return bro_df,file_features
def create_df_conn(file):
    with open(file,'r') as f:
        bro_df=pd.DataFrame( json.load(f))
    bro_df=clean_df(bro_df)
    bro_df.rename(columns = {'id.resp_p':'resp_p','id.orig_h':'orig_h'}, inplace = True)
    bro_df['duration']=bro_df['duration'].astype(float).apply(lambda x: str(math.floor(x)))
    return bro_df,conn_features
def create_df_http(file):
    with open(file,'r') as f:
        bro_df=pd.DataFrame( json.load(f))
    bro_df=clean_df(bro_df)
    bro_df.rename(columns = {'id.resp_p':'resp_p','id.orig_h':'orig_h'}, inplace = True)
    return bro_df,http_features

import subprocess
import os
import csv
import paramiko

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
def get_zeek_logs():
    try:
        res,err=ge#t_remote_stdout_sudo('sudo bash /home/cristiana/communicate.sh')
        output=subprocess.check_output(['zeek','-C','-r','/home/cristiana/capfiles/capfile'])
    except subprocess.CalledProcessError as e:
        print(e.output)
    output=subprocess.call('mv /home/cristiana/pyqt/two_windows/sockets/server/*.log /home/cristiana/pyqt/two_windows/logs/',shell=True)
    csv_to_json('/home/cristiana/pyqt/two_windows/logs/')
import numpy as np
# get_zeek_logs()


bro_df,features=create_df_file(file_log_file)  

bro_matrix=to_matrix.fit_transform(bro_df[features],normalize=True) 
from sklearn.decomposition import PCA
from sklearn.manifold import trustworthiness
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt

# get_pca_metric(bro_matrix)

pca = PCA(n_components=60)
X_selected = pca.fit_transform(bro_matrix)
# X_selected=bro_matrix
print(bro_matrix.shape)
print(X_selected.shape)

model=pickle.load(open('/home/cristiana/pyqt/two_windows/sockets/server/model.sav','rb'))
print(f'----------> Using model: {model}')
# model=IsolationForest(contamination=0.12)
model.fit(X_selected)

features.append('score')
bro_df['score']=model.decision_function(X_selected)
odd_df=bro_df[features][model.predict(X_selected) == -1] #y=-1 abnormal y=1 normal
def jitter(arr):
    stdev = .02*(max(arr)-min(arr))
    return arr + np.random.randn(len(arr)) * stdev
odd_matrix = to_matrix.fit_transform(odd_df)


# get_elbow_score()
for k in range(9,3,-1):
# k=9
    try:
        print(f'----------> Clustering data for {k} clusters')
        clustering = KMeans(n_clusters=k).fit_predict(odd_matrix) 
        pca = PCA(n_components=3).fit_transform(odd_matrix)

        # Now we can put our ML results back onto our dataframe!
        odd_df['x'] = pca[:, 0] # PCA X Column
        odd_df['y'] = pca[:, 1] # PCA Y Column
        odd_df['cluster'] = clustering
        
        odd_df['jx'] = jitter(odd_df['x'])
        odd_df['jy'] = jitter(odd_df['y'])

        cluster_groups = odd_df.groupby('cluster')
 
        colors = {0:'green', 1:'blue', 2:'red',3:'yellow', 4:'purple', 5:'brown',6:'pink',7:'olive',8:'cyan',9:'gray'}
       # fig, ax = plt.subplots()
        for key, group in cluster_groups:
            #group.plot(ax=ax, kind='scatter', x='jx', y='jy', alpha=0.5, s=250,
                  #  label='Cluster: {:d}'.format(key), color=colors[key])
            print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
            print(group[features].head())
        #plt.show()
        # break #daca nu a a aparut nicio exceptie, ramanem cu nr maxim de clustere
    except:
        pass



