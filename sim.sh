#!/bin/bash

curr_dir="${PWD##*/}"

function pause() {
   read -p "$*"
}

# initial
rm -f fcd.xml rou.xml vehroutes.xml attackerIDs.txt accusation.txt
rm -rf pic

pause 'Press [Enter] key to continue...'

## construct routing
echo "construct routing"
activitygen -v false -b 21600 -e 64800 --duration-d 2 -n net.xml -s stat.xml -o rou.xml --random

## Start simulation
sumo sumo.cfg

## generate fcd file
echo "generate fcd file"
sumo --net-file net.xml -r rou.xml --fcd-output fcd.xml

## get malicious vehicle ids
python generate_attacker_ids.py

## generate accusation graph
echo "generate accusation graph"
python generate_accusation_relationship.py
python generate_accusation_graph.py
