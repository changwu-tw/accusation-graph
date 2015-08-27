#!/usr/bin/env python

"""
@file   generate_accusation_relationship.py
@author Chang-Wu Chen

@para   fcd.xml
"""


import os
import pandas as pd
import random
import sys

from lxml import etree
from scipy import spatial

p_pf = 1e-7
p_mb = 0.01
p_pd = 0.01
radius = 50
period = 10

_, curr_dir = os.path.split(os.getcwd())
columns = ['id', 'x', 'y']


def init():
    global bad_vids
    with open('attackerIDs.txt') as f:
        bad_vids = f.read().split(',')


def decision(p):
    return random.random() < p


def getVid(pid):
    return pid.split(':')[0]


def fastiter(context, handler):
    for event, element in context:
        handler(element)
        element.clear()
        while element.getprevious() is not None:
            del element.getparent()[0]
    del context


def handler(element):
    t = int(float(element.get('time')))
    if t % period == 0:
        vehicles = element.xpath('vehicle')
        if vehicles:
            data = []
            for vehicle in vehicles:
                data.append([vehicle.get('id'), vehicle.get('x'), vehicle.get('y')])

            # Get vehicle's position
            df = pd.DataFrame(data, columns=columns)
            x, y = df.x, df.y
            positions = zip(x.ravel(), y.ravel())
            tree = spatial.cKDTree(positions)

            posRepeated = []
            for pos in positions:
                if pos not in posRepeated:
                    # Get a list of the indices of the neighbors of vehicle
                    df_index = tree.query_ball_point(pos, radius)
                    if len(df_index) > 1:
                        nearby_vehicles = []
                        for index in df_index:
                            nearby_vehicles.append(df.iloc[index].id)
                            posRepeated.append((df.iloc[index].x, df.iloc[index].y))
                            posRepeated.append(pos)

                        for nearby_vehicle in nearby_vehicles:
                            # Decide vehicle is good or bad
                            if getVid(nearby_vehicle) in bad_vids:
                                if decision(p_mb):
                                    for pid in nearby_vehicles:
                                        if pid != nearby_vehicle and decision(p_pd):
                                            f.write('{0} {1} {2} {3}\n'.format(pid, nearby_vehicle, 'T', t))
                            else:
                                if decision(p_pf):
                                    for pid in nearby_vehicles:
                                        if pid != nearby_vehicle and decision(p_pd):
                                            f.write('{0} {1} {2} {3}\n'.format(pid, nearby_vehicle, 'F', t))


if __name__ == '__main__':
    init()

    with open('accusation.txt', 'w') as f:
        context = etree.iterparse('fcd.xml', events=('end',), tag='timestep')
        fastiter(context, handler)
