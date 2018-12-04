# µIDS
simple python network-based signature intrusion detection system

## Required Packages
* scapy
* netifaces

## Install && Testing
    git clone ../acsl_IDS.git
    python3 -m venv acsl_IDS
    cd acsl_IDS
    pip3 install -r requirements.txt
    sudo python3 main.py wlp4s0 default.rules

## Running sender.py
    sudo python3 sender.py enp0s8

## Rules

list of rules in default.rules

list evaluation-rules in eval.rules

structure

    PROTO [!]IP|any:[!]PORT(RANGE)|any <>|-> [!]IP|any:[!]PORT(RANGE)|any *PAYLOAD

example

    ICMP 192.168.178.22:any -> 1.1.1.1:[500-510] * # -IDS
