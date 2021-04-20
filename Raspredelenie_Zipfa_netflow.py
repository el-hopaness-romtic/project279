# coding=utf-8
import sys
import re
import array
import operator
import os
import glob
import matplotlib.pyplot as plt
import numpy as np

# имена nfcapd файлов
name = []

# заносить статистику (потоки/трафик) для отдельных ip
static = {}
static_tcp = {}
static_udp = {}
l = 5
for filename in glob.glob('nfcapd.20*'):
    name.append(filename)
name.sort()

for i in name:
    # если необходим анализ определённого файла
    # if name.index(i) != 687:
    #     continue

    # приведение файлов в человекочитаемый формат
    command = 'nfdump -r ' + i + '   -o "fmt:%td,%pr,%sa,%sp,%da,%dp,%pkt,%byt,%fl,%bpp" > tt.text' + str(l)
    os.system(command)

    with open('tt.text' + str(l)) as f:
        srcIP = []
        flow = []
        protocol = []
        bytes = []
        for line in f:
            row = line.split(',')

            # пропуск лишних строк в начале и конце файла
            if re.search('Duration', line):
                continue
            if re.search('Summary', line):
                break

            # извлечение информации и распределение её по массивам
            protocol.append(row[1])
            srcIP.append(row[2])
            flow.append(row[8])
            bytes.append(row[7])

            flow[-1] = flow[-1].strip(' ')
            srcIP[-1] = srcIP[-1].strip(' ')
            protocol[-1] = protocol[-1].strip(' ')
            bytes[-1] = bytes[-1].strip(' ')

            # рассчёт траффика и потоков от каждого ip адреса
            if srcIP[-1] in static:
                static[srcIP[-1]] = int(flow[-1]) + int(static[srcIP[-1]])
            else:
                static[srcIP[-1]] = int(flow[-1])
            if 'M' in bytes[-1]:
                bytes[-1] = bytes[-1].strip(' M')
                bytes[-1] = str(int(float(bytes[-1]) * 1000000))

            if protocol[-1] == 'TCP':
                if srcIP[-1] in static_tcp:
                    static_tcp[srcIP[-1]] = int(bytes[-1]) + int(static_tcp[srcIP[-1]])
                else:
                    static_tcp[srcIP[-1]] = int(bytes[-1])

            if protocol[-1] == 'UDP':
                if srcIP[-1] in static_udp:
                    static_udp[srcIP[-1]] = int(bytes[-1]) + int(static_udp[srcIP[-1]])
                else:
                    static_udp[srcIP[-1]] = int(bytes[-1])
        l = l + 5
        # break

# массивы для последующей отрисовки
m = []
m1 = []
m2 = []
ko = sorted(static.items(), key=lambda item: item[1], reverse=True)
ko1 = sorted(static_tcp.items(), key=lambda item: item[1], reverse=True)
ko2 = sorted(static_udp.items(), key=lambda item: item[1], reverse=True)
for k, v in ko:
    m.append(v)
for k, v in ko1:
    m1.append(v)
for k, v in ko2:
    m2.append(v)

# отрисовка графиков
plot1 = plt.figure(1)
plt.scatter(np.log10(np.arange(1, len(ko) + 1)), np.log10(m), label='Total', c='blue')
plt.legend()

plot2 = plt.figure(2)
plt.scatter(np.log10(np.arange(1, len(ko1) + 1)), np.log10(m1), label='TCP', c='red')
plt.legend()

plot3 = plt.figure(3)
plt.scatter(np.log10(np.arange(1, len(ko2) + 1)), np.log10(m2), label='UDP', c='orange')
plt.legend()

plot4 = plt.figure(4)
plt.scatter(np.log10(np.arange(1, len(ko) + 1)), np.log10(m), label='Total', c='blue')
plt.scatter(np.log10(np.arange(1, len(ko1) + 1)), np.log10(m1), label='TCP', c='red')
plt.scatter(np.log10(np.arange(1, len(ko2) + 1)), np.log10(m2), label='UDP', c='orange')
plt.legend()

plt.show()
