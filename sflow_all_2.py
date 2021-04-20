# coding=utf-8
import operator
import os
import glob
import matplotlib.pyplot as plt
import numpy as np
import sys
import re
import array
import time
import requests
from json import loads
import math
from threading import Timer

# пороговые значения
threshold_flow = 2000
threshold_TCP = 70000
threshold_UDP = 70000

i = 100
headers = {
    'Content-Type': 'application/json'
}

url = 'http://192.168.1.1:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:564037746053536/table/100/'


# функция, в которой ip адрес выносится из чёрного списка, вызывается при прохождении пяти минут с момента блокировки
def delete(i, k):
    response = requests.delete(
        'http://192.168.1.1:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:564037746053536/table/100/flow/' +
        str(i),
        headers=headers,
        auth=('admin', 'admin')
    )
    if response:
        print k + 'was successfully removed from the block list after 5 minutes'


while True:
    timeout = time.time() + 60 * 5  # засекаем пять минут
    static = {}
    static_tcp = {}
    static_udp = {}

    for line in iter(sys.stdin.readline, ''):
        if time.time() > timeout:
            break
        # расшифровка json
        datagram = loads(line)

        # анализ вывода sflow
        samples = datagram["samples"]
        for sample in samples:
            sampleType = sample["sampleType"]
            elements = sample["elements"]
            if sampleType == "FLOWSAMPLE":
                inputPort = sample["inputPort"]
                if inputPort == "2" or inputPort == "24":
                    for element in elements:
                        try:
                            src = element["srcIP"]
                            dst = element["dstIP"]
                            pktsize = element["sampledPacketSize"]
                            protocol = element["IPProtocol"]
                            if str(src) in static:
                                static[str(src)] = int(static[str(src)]) + 1
                            else:
                                static[str(src)] = 1
                            if protocol == "6":  # TCP
                                if str(src) in static_tcp:
                                    static_tcp[str(src)] = int(static_tcp[str(src)]) + int(pktsize)
                                else:
                                    static_tcp[str(src)] = int(pktsize)
                            if protocol == "17":  # UDP
                                if str(src) in static_udp:
                                    static_udp[str(src)] = int(static_udp[str(src)]) + int(pktsize)
                                else:
                                    static_udp[str(src)] = int(pktsize)
                        except KeyError:
                            pass
    print static
    print static_tcp
    print static_udp
    ko = sorted(static.items(), key=lambda item: item[1], reverse=True)
    ko1 = sorted(static_tcp.items(), key=lambda item: item[1], reverse=True)
    ko2 = sorted(static_udp.items(), key=lambda item: item[1], reverse=True)

    # блокировка подозрительного ip адреса при превышении порога количества потоков, tcp трафика, udp трафика
    for k, v in ko:
        if v > threshold_flow:
            data = '{"flow":[{"table_id":"100","id":"' + str(
                i) + '", "priority":"1000","hard-timeout":300,"cookie":"0x102","match":{"ethernet-match":{"ethernet-type":{"type":"0x0800"}},"ipv4-source":"' + k + '/32","ipv4-destination":"192.168.2.1/32"},"instructions":{"instruction":[{"order":0,"apply-actions":{"action":[{"order":0,"drop-action":{}}]}}]}}]}'
            print data
            response = requests.post(url, headers=headers, data=data, auth=('admin', 'admin'))
            if response:
                print k + ' has added Successfully to the block list!'
            t1 = Timer(300.0, delete, [i, k])
            t1.start()
            i = i + 1
    for k, v in ko1:
        if v > threshold_TCP:
            data = '{"flow":[{"table_id":"100","id":"' + str(
                i) + '","priority":"1001","hard-timeout":300,"cookie":"0x102","match":{"ethernet-match":{"ethernet-type":{"type":"0x0800"}},"ipv4-source":"' + k + '/32","ipv4-destination":"192.168.2.1/32"},"instructions":{"instruction":[{"order":0,"apply-actions":{"action":[{"order":0,"drop-action":{}}]}}]}}]}'
            print data
            response = requests.post(url, headers=headers, data=data, auth=('admin', 'admin'))
            if response:
                print k + ' has added Successfully to the block list!'
            t2 = Timer(300.0, delete, [i, k])
            t2.start()
            i = i + 1
    for k, v in ko2:
        if v > threshold_UDP:
            data = '{"flow":[{"table_id":"100","id":"' + str(
                i) + '","priority":"1002","hard-timeout":300,"cookie":"0x102","match":{"ethernet-match":{"ethernet-type":{"type":"0x0800"}},"ipv4-source":"' + k + '/32","ipv4-destination":"192.168.2.1/32"},"instructions":{"instruction":[{"order":0,"apply-actions":{"action":[{"order":0,"drop-action":{}}]}}]}}]}'
            print data
            response = requests.post(url, headers=headers, data=data, auth=('admin', 'admin'))
            if response:
                print k + ' has added Successfully to the block list!'
            t3 = Timer(300.0, delete, [i, k])
            t3.start()
            i = i + 1
