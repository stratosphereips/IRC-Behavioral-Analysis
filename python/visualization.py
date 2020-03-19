#!/usr/bin/env python
# coding: utf-8

# # IRC Behavioral Analysis - Visualization

# ### Imports

# In[1]:


import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from scipy import stats


# ## Loading Data

# In[2]:


import os


log_names_mal = ['03','04','34','39','42','51','56','62']
log_names_benign = ['irc1']
log_names = log_names_mal + log_names_benign

# project_dir = '/Users/preneond/Documents/Work/Stratosphere/IRC-Research/IRC-Behavioral-Analysis/' 
project_dir = '/home/prenek/IRC-Behavioral-Analysis/'

log_dir = os.path.join(project_dir, 'zeek/logs/')
out_dir = os.path.join(project_dir, 'python/out/')
plot_dir = os.path.join(project_dir, 'python/plots/')

fn_join_freq = 'join_freq.log'
fn_lev_dist = 'lev_dist.log'

logs_fn_join = [os.path.join(out_dir,l, fn_join_freq) for l in log_names]
logs_fn_join_mal = [os.path.join(out_dir,l, fn_join_freq) for l in log_names_mal]
logs_fn_join_benign = [os.path.join(out_dir,l, fn_join_freq) for l in log_names_benign]

logs_fn_privmsg = [os.path.join(out_dir,l, fn_lev_dist) for l in log_names]
logs_fn_privmsg_mal = [os.path.join(out_dir,l,fn_lev_dist) for l in log_names_mal]
logs_fn_privmsg_benign = [os.path.join(out_dir,l, fn_lev_dist) for l in log_names_benign]



# FIXME: read csv in chunks because the log is too big
df_privmsg_benign = None
chunksize = 10 ** 5
# df_tmp = None
for pcap, log in zip(log_names_benign, logs_fn_privmsg_benign):
    print(pcap)
    df_tmp = pd.read_csv(log, sep=';', encoding='utf-8', chunksize=chunksize)
    df_tmp = pd.concat(df_tmp, ignore_index=True)
    df_tmp['pcap'] = pcap
    df_tmp['malicious'] = 0
    df_privmsg_benign = pd.concat([df_privmsg_benign, df_tmp], ignore_index=True, sort=True)
    df_privmsg_benign.drop(["Unnamed: 0"], axis=1, inplace=True)

df_privmsg_benign['lev_dist'] =  df_privmsg_mal['lev_dist'].apply(lambda x: ast.literal_eval(x))
df_privmsg_benign.head()


# In[ ]:


df_privmsg_benign.describe()


# In[ ]:


fig = plt.figure()
for i, df_el in df_privmsg_benign.iterrows():
    sns.distplot(df_el['lev_dist'])
    plt.title('Benign PRIVMSG - Distribution plot of pairwise distance')
    plt.xlabel('Levenshtein distance')
    plt.ylabel('Distribution')
legend_titles = list(map(lambda x: ": ".join(x), list(zip(df_privmsg_mal['pcap'], df_privmsg_mal['channel']))))   
fig.legend(legend_titles)
plt.savefig(os.path.join(plot_dir,'benign_privmsg_distplot_all.pdf'), format='pdf')

