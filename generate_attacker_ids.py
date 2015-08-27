#!/usr/bin/env python

"""
@file   generate_attacker_ids.py
@author Chang-Wu Chen

@para   vehroutes.xml
"""

import random

from collections import Counter
from lxml import etree

import helper

mostCommonNumber = 10

# ratio of the malicious vehicles
ratio = 0.05


def fastiter(context, handler):
    vids = []
    pids = []

    for event, element in context:
        vid, pid = handler(element)
        vids.append(vid)
        pids.append(pid)
        element.clear()
        while element.getprevious() is not None:
            del element.getparent()[0]
    del context
    return vids, pids


def handler(element):
    """Checking
    # if 'carIn440' in element.get('id'):
    #     day1, time1 = helper.getTime(element.get('depart'))
    #     day2, time2 = helper.getTime(element.get('arrival'))
    #     print element.get('id'), day1, time1, time2
    """

    return element.get('id').split(':')[0], element.get('id')


def showInfo(vids, pids, number_of_attackers):
    print '# of unique vehicle: {}'.format(len(set(vids)))
    print '# of total vehicles: {}'.format(len(set(pids)))
    print '# of malicious vehicles: {}'.format(number_of_attackers)
    print


def showMostCommonVehicles(vids, num=mostCommonNumber):
    print Counter(vids).most_common()[:num]
    print


def getMaliciousVehileIDs(uids, number_of_attackers):
    random.shuffle(uids)
    return uids[:number_of_attackers]


if __name__ == '__main__':
    context = etree.iterparse('vehroutes.xml', events=('end',), tag='vehicle')
    vids, pids = fastiter(context, handler)

    # Get unique vehcile ids
    uids = list(set(vids))
    number_of_attackers = int(len(uids) * ratio)

    with open('attackerIDs.txt', 'w') as f:
        f.write(','.join(getMaliciousVehileIDs(uids, number_of_attackers)))
        
    with open('vehicleInfo.txt', 'w') as f:
        f.write(showInfo(vids, pids, number_of_attackers))

    ## showInfo(vids, pids, number_of_attackers)
    ## showMostCommonVehicles(vids)
