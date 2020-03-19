#!/usr/bin/env python
# coding: utf-8

# # IRC Behavioral Analysis - Visualization

# ### Imports

# In[5]:


import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from scipy import stats


# ## Loading Data

# In[6]:


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


# ## Number of Users in Channel per Day

# ### Data Import

# In[7]:


## JOIN LOGS
df_join_mal = None
df_tmp = None
for pcap, log in zip(log_names_mal, logs_fn_join_mal):
    df_tmp = pd.read_csv(log, sep=';', encoding='utf-8')
    df_tmp['pcap'] = pcap
    df_tmp['malicious'] = 1
    df_join_mal = pd.concat([df_join_mal, df_tmp], ignore_index=True, sort=True)
    df_join_mal.drop(["Unnamed: 0"], axis=1, inplace=True)

df_join_benign = None
df_tmp = None
for pcap, log in zip(log_names_benign, logs_fn_join_benign):
    print(log)
    df_tmp = pd.read_csv(log, sep=';', encoding='utf-8')
    df_tmp['pcap'] = pcap
    df_tmp['malicious'] = 0
    df_join_benign = pd.concat([df_join_benign, df_tmp], ignore_index=True, sort=True)
    df_join_benign.drop(["Unnamed: 0"], axis=1, inplace=True)

df_join = pd.concat([df_join_mal, df_join_benign], ignore_index=True)
df_join.head()


# In[118]:


def ircjoin_visualize(df, log, channel):
    plt.bar(df['date'], df['users_count'])
    plt.title('pcap {}, channel {}'.format(log,channel))
    plt.xlabel('dates')
    plt.ylabel('users')
    plt.show()

# for l in log_names:
#     df_join_tmp = df_join[df_join['pcap'] == l]
#     for channel,df in df_join_tmp.groupby('channel'):
#         ircjoin_visualize(df,l,channel)


# ## Levenshtein Distance of Messages in Channel

# ### Data Import 

# In[11]:


## PRIVMSG LOGS
df_privmsg_mal = None
df_tmp = None
for pcap, log in zip(log_names_mal, logs_fn_privmsg_mal):
    df_tmp = pd.read_csv(log, sep=';', encoding='utf-8')
    df_tmp['pcap'] = pcap
    df_tmp['malicious'] = 1
    df_privmsg_mal = pd.concat([df_privmsg_mal, df_tmp], ignore_index=True, sort=True)
    df_privmsg_mal.drop(["Unnamed: 0"], axis=1, inplace=True)

import ast
df_privmsg_mal['lev_dist'] =  df_privmsg_mal['lev_dist'].apply(lambda x: ast.literal_eval(x))
df_privmsg_mal.head()


# In[12]:


df_privmsg_mal['lev_dist_mean'] = df_privmsg_mal['lev_dist'].apply(lambda x: np.mean(x))
df_privmsg_mal['lev_dist_std'] = df_privmsg_mal['lev_dist'].apply(lambda x: np.std(x))
df_privmsg_mal.head()


# ### Bubble plot

# In[191]:


def ircprivmgs_visualize(lev_dist_arr,num_sources_arr, num_messages_arr):
    cm = plt.cm.get_cmap('jet')
    x = np.array(num_sources_arr)
    y = np.array(num_messages_arr)
    z = 5*np.power(np.array(lev_dist_arr),2)
    
    fig, ax = plt.subplots()
    sc = ax.scatter(x,y,s=z,c=z,cmap=cm, alpha=0.4)
    ax.grid(alpha=0.5)
    fig.colorbar(sc)
    plt.xlabel('Number of Users in Channel')
    plt.ylabel('Number of Messages')
    plt.title('Levenstein Distance of Messages per Capture')
    plt.show()


df_privmsg_mal_notna = df_privmsg_mal[df_privmsg_mal['lev_dist_mean'].notna()]
colors = []
for pcap in df_privmsg_mal_notna.pcap.unique():
    df_tmp = df_privmsg_mal_notna[df_privmsg_mal_notna['pcap'] == pcap]
    ircprivmgs_visualize(df_tmp['lev_dist_mean'], df_tmp['num_sources'], [-1] * df_tmp.shape[0])
    


# for l in log_names:
# for log_name,l in zip(log_names,logs_privmsg):
#     for ll in l:
#         channel, lev_dists_pairwise = ll
#         lev_dist_arr.append(np.mean(lev_dists_pairwise))
#         num_messages_arr.append(len(lev_dists_pairwise))
#         num_sources_arr.append(np.random.randint(10))

# ircprivmgs_visualize(lev_dist_arr, num_sources_arr, num_messages_arr)


# ## Distribution plot

# ### Malicious samples

# In[13]:


df_privmsg_mal.describe()


# In[14]:


fig = plt.figure()
for i, df_el in df_privmsg_mal.iterrows():
    sns.distplot(df_el['lev_dist'])
    plt.title('Malicious PRIVMSG - Distribution plot of pairwise distance')
    plt.xlabel('Levenshtein distance')
    plt.ylabel('Distribution')
legend_titles = list(map(lambda x: ": ".join(x), list(zip(df_privmsg_mal['pcap'], df_privmsg_mal['channel']))))   
fig.legend(legend_titles)
plt.savefig(os.path.join(plot_dir,'privmsg_distplot_all.pdf'), format='pdf')


# 95 quantile

# In[15]:


from scipy import stats

stats.describe(df_privmsg_mal[df_privmsg_mal['pcap'] == '56']['lev_dist'].iloc[0])


# In[16]:


fig = plt.figure()
for i, df_el in df_privmsg_mal.iterrows():
    if df_el['pcap'] == '56': 
        continue
    sns.distplot(df_el['lev_dist'])
    plt.title('Malicious PRIVMSG - Distribution plot of pairwise distance')
    plt.xlabel('Levenshtein distance')
    plt.ylabel('Distribution')

legend_titles = list(map(lambda x: ": ".join(x), list(zip(df_privmsg_mal['pcap'], df_privmsg_mal['channel']))))   
fig.legend(legend_titles)
plt.savefig(os.path.join(plot_dir, 'privmsg_distplot_no56.pdf'), format='pdf')


# ### Benign Samples

# In[27]:


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

