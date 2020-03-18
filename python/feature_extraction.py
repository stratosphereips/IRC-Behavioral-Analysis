#!/usr/bin/env python
# coding: utf-8

# # IRC Behavioral Analysis

# ### Imports

# In[45]:


import zat
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from zat.log_to_dataframe import LogToDataFrame
from zat.bro_log_reader import BroLogReader
from collections import defaultdict


# ## Loading Data

# In[73]:


import os

log_names_mal = ['03','04','34','39','42','51','56','62']
log_names_benign = ['irc1']
log_names = log_names_mal + log_names_benign

project_dir = '/home/prenek/IRC-Behavioral-Analysis/' 
log_dir = os.path.join(project_dir, 'zeek/logs/')
out_dir = os.path.join(project_dir, 'python/out/')

fileout_join_freq = 'join_freq.log'
fileout_lev_dist = 'lev_dist.log'

logs_fn_join = [os.path.join(log_dir,l,'irc_join.log') for l in log_names]
logs_fn_join_mal = [os.path.join(log_dir,l,'irc_join.log') for l in log_names_mal]
logs_fn_join_benign = [os.path.join(log_dir,l,'irc_join.log') for l in log_names_mal]

logs_fn_privmsg = [os.path.join(log_dir,l,'irc_privmsg.log') for l in log_names]
logs_fn_privmsg_mal = [os.path.join(log_dir,l,'irc_privmsg.log') for l in log_names_mal]
logs_fn_privmsg_benign = [os.path.join(log_dir,l,'irc_privmsg.log') for l in log_names_benign]


# In[47]:
def load_logs(file):
    logs_arr = []
    if not os.path.isfile(file):
        return logs_arr
    
    reader = BroLogReader(file)
    for log in reader.readrows():
        # log is in dictionary format
        logs_arr.append(log)

    return logs_arr


# In[64]:


logs_join_mal = list(map(lambda x: load_logs(x),logs_fn_join))
logs_join_benign = list(map(lambda x: load_logs(x),logs_fn_join))
logs_join = logs_join_mal + logs_join_benign


logs_privmsg_mal = list(map(lambda x: load_logs(x),logs_fn_privmsg_mal))
logs_privmsg_mal = [list(filter(lambda x: x['target'].startswith('#'), log)) for log in logs_privmsg_mal]

logs_privmsg_benign = list(map(lambda x: load_logs(x),logs_fn_privmsg_mal))
logs_privmsg_benign = [list(filter(lambda x: x['target'].startswith('#'), log)) for log in logs_privmsg_benign]

logs_privmsg = logs_privmsg_mal + logs_privmsg_benign


# ### Divide logs by channels

# In[65]:

from collections import defaultdict
logs_join_divided = []
for logs in logs_join:
    logs_per_channel = defaultdict(lambda: [])    
    for log in logs:
        logs_per_channel[log['channel']].append(log)
    logs_join_divided.append(logs_per_channel)


# In[66]:


logs_privmsg_divided = []
for logs in logs_privmsg_benign:
    logs_per_channel = defaultdict(lambda: [])    
    for log in logs:
        logs_per_channel[log['target']].append(log)
    logs_privmsg_divided.append(logs_per_channel)


# ## Number of Users in Channel per Day

# In[67]:

import json

def ircjoin_compute(logs):
    if len(logs) == 0:
        return None, None

    logs_ts = list(map(lambda x: x['ts'].date(), logs))

    # first ts of join command
    ts_min = min(logs_ts)
    ts_max = max(logs_ts)
#     print('min date: {}, max date: {}'.format(ts_min, ts_max))
    span = ts_max - ts_min
    
    dates = [ts_min+timedelta(days=i) for i in range(span.days+1)]

    ## count how many join commands are in which day 
    logs_per_day = defaultdict(lambda: 0)
    for v in logs_ts:
        logs_per_day[v] += 1
    
    dates_count = []
    count = 0
    for d in dates:
        count += logs_per_day[d]
        dates_count.append(count)
    
    return dates, dates_count


def ircjoin_visualize(dates, dates_count):
    plt.bar(dates,dates_count)
    plt.show()


# In[68]:

#print('ircjoin...')
#for ln, l in zip(log_names, logs_join_divided):
#    fn = os.path.join(out_dir, ln, fileout_join_freq)
#    df_join = pd.DataFrame(columns=['channel','date','users_count'])
#    
#    for l_k in l.keys():
#        log = l[l_k]
#        d_arr, dc_arr = ircjoin_compute(log)
#        # ircjoin_visualize(d, dc)
#        for d, dc in zip(d_arr,dc_arr):
#            df_join = df_join.append({'channel': l_k, 'date': d, 'users_count': dc}, ignore_index=True)
#    
#    print(fn)
#    df_join.to_csv(fn, sep=';', encoding='utf-8')
#
#
# ## Levenshtein Distance of Messages in Channel

# In[69]:


import itertools
from Levenshtein import distance as levenshtein_distance

def compute_levenshtein_distance(logs_msg):
    combs = itertools.combinations(logs_msg, 2)
    dist_lev_arr = []
    for msg1, msg2 in combs:
        dist_lev_arr.append(levenshtein_distance(msg1,msg2))
        
    return dist_lev_arr


# ### Bubble plot

# In[70]:


from multiprocessing import Pool

n = len(logs_privmsg)

print('ircprivmsg..')

def compute_lev_dist_per_channel(l_k):
    print('channel: ', l_k)
    # compute levenshtein distance
    logs_msg = [log['msg'] for log in logs[l_k]]
    logs_lev_dist = compute_levenshtein_distance(logs_msg)
    # compute number of msg's senders per channel
    sources = set([log['source'] for log in logs[l_k]])
    # print('sources: ', len(sources))
    return {'channel': l_k, 'num_sources': len(sources), 'lev_dist': logs_lev_dist}


for ln, logs in zip(log_names_benign, logs_privmsg_divided):
    with Pool() as pool:
        fn = os.path.join(out_dir, ln, fileout_lev_dist)
        print(fn)
        print(logs.keys())
        # loop through channels            
        data = pool.map(compute_lev_dist_per_channel,logs.keys())     
        df_privmsg = pd.DataFrame(data)
        df_privmsg.to_csv(fn, sep=';', encoding='utf-8')
        #print('lev_dist: ', logs_lev_dist)

