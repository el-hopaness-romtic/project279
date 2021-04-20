# coding=utf-8
import sys
import re
import array
import operator
import os
import glob
import matplotlib.pyplot as plt

total2 = []
# total
time = []

# имена nfcapd файлов
name = []
l = 5
for filename in glob.glob('nfcapd.20*'):
    name.append(filename)
name.sort()

for i in name:
    # приведение файлов в человекочитаемый формат
    command = 'nfdump -r ' + i + '  -o "fmt:%td,%pr,%sa,%sp,%da,%dp,%pkt,%byt,%fl,%bpp" > tt.text' + str(l)
    os.system(command)

    with open('tt.text' + str(l)) as f:
        srcIP = []
        flow = []
        static = {}
        for line in f:
            row = line.split(',')

            # пропуск лишних строк в начале и конце файла
            if re.search('Duration', line):
                continue
            if re.search('Summary', line):
                break

            # извлечение информации о количестве потоков
            srcIP.append(row[2])
            flow.append(row[8])
            flow[-1] = flow[-1].strip(' ')
            srcIP[-1] = srcIP[-1].strip(' ')

            # рассчёт потоков от каждого ip адреса
            if srcIP[-1] in static:
                static[srcIP[-1]] = int(flow[-1]) + int(static[srcIP[-1]])
            else:
                static[srcIP[-1]] = int(flow[-1])
        time.append(l)
        max_idx, max_val = max(static.iteritems(), key=operator.itemgetter(1))
        total2.append([l, max_idx, max_val])
        f.close()
        l = l + 5

# вывести пороговые значения за пятиминутные промежутки времени
for k, v, l in total2:
    print k, v, l