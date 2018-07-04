import os
import json

reports = {}
for report_file_name in filter(lambda f: '.report' in f, os.listdir()):
    with open(report_file_name) as report_file:
        perf_report = json.load(report_file)
        mode_name = perf_report['mode']
        if mode_name not in reports:
            reports[mode_name] = {}
            reports[mode_name]['count'] = 0
        reports[mode_name]['count'] += 1

        for stat, value in perf_report.items():
            if stat == 'mode':
                continue
            if stat not in reports[mode_name]:
                reports[mode_name][stat] = 0
            reports[mode_name][stat] += value

for mode, stats in reports.items():
    count = stats['count']
    for stat, value in stats.items():
        if stat == 'mode' or stat == 'count':
            continue
        reports[mode][stat] = value/count

print(reports)