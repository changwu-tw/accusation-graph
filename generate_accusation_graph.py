#!/usr/bin/env python

"""
@file   generate_accusation_graph.py
@author Chang-Wu Chen

@para   fcd.xml
"""

from __future__ import division

import os
import math
import networkx as nx
import numpy as np
import pandas as pd
import helper

index = 0

# capture event each 180 seconds
capture_time = 180


def saveGraph(G, filename):
    global index
    index += 1
    helper.saveToDotGraph(G, 'pic/{:0>3d}_{}'.format(index, filename))


def init():
    if not os.path.exists('pic'):
        os.makedirs('pic')


if __name__ == '__main__':
    init()

    # Generate a cert-cert graph
    df = pd.read_csv('accusation.txt', delimiter=' ', header=None)
    df.columns = ['u', 'v', 'type', 'time']

    # G = nx.DiGraph()
    begin = (int)(min(df.time))
    finish = (int)(max(df.time))

    for i in xrange(begin, finish + 1, capture_time):
        H = nx.DiGraph()

        # Retrieve graph per minute
        data = df[np.logical_and(df['time'] > i, df['time'] < (i + capture_time))]

        if data.empty is not True:
            for _, row in data.iterrows():
                H.add_edge(row['u'], row['v'])

            day1, time1 = helper.getTime(i)
            day2, time2 = helper.getTime(i + capture_time)
            filename = '{}_{}_{}'.format(day1, time1, time2)
            saveGraph(H, filename)
