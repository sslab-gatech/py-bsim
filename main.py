from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
import py_compile
import subprocess
import sys
import time

import py_bsim
import py_bsim_serialization


print('Loading weights...')
weights = py_bsim.BSimWeights.load_from_path('../ghidra/ghidra_11.0.1_PUBLIC/Ghidra/Features/BSim/data/lshweights_64.xml')

# MONTHS_AND_REVS = [('2023-10', 9), ('2023-11', 6), ('2023-12', 6), ('2024-01', 6)]
MONTHS_AND_REVS = [('2023-10', 9), ('2023-11', 6), ('2023-12', 6), ('2024-01', 6)]

start = time.perf_counter()
functions = {}
for month, num_revs in MONTHS_AND_REVS:
    # note: I tried doing this multi-threaded -- ended up being slower
    functions[month] = {}
    for r in range(1, num_revs + 1):
        print(f'Loading signatures ({month} r{r})')
        exe_path = Path(f'../bsim-android-dataset/android14-6.1-{month}_r{r}_vmlinux')
        md5 = hashlib.md5(exe_path.read_bytes()).hexdigest()
        sigs_path = Path(f'../bsim-android-dataset/bsim_signatures/sigs_{md5}')
        if sigs_path.is_file():
            functions[month][r] = py_bsim_serialization.load_signatures_xml_cached(sigs_path).as_combined_function_dict()
        else:
            print(f'WARNING: no signatures for {month} r{r}')
print(f'Loaded in {time.perf_counter() - start:0.3f}s')  # 102s serially

print('Calculating diffs within each month')
diffs = {}
for month, num_revs in MONTHS_AND_REVS:
    diffs[month] = {}
    for r in range(2, num_revs + 1):
        diffs[month][r] = {}
        for name in set(functions[month][r - 1]) & set(functions[month][r]):
            diff = py_bsim.lshcosine_difference(functions[month][r - 1][name], functions[month][r][name], weights)
            if not py_bsim.lshcosine_is_zero(diff):
                diffs[month][r][name] = diff

    print(f'Diffs per revision in {month}: { {i: len(diffs[month][i]) for i in sorted(diffs[month])} }')

# # TEMP
# py_bsim.DEBUG = True
# similarity = py_bsim.lshcosine_similarity(diffs[1]['q931_help'], diffs[5]['q931_help'], weights)
# confidence = py_bsim.lshcosine_confidence(diffs[1]['q931_help'], diffs[5]['q931_help'], weights)
# print(f'r1 patch for q931_help is similar to r5 patch for q931_help (similarity={similarity}, confidence={confidence})')
# py_bsim.lshcosine_print(diffs[1]['q931_help'], weights, name=f'r1 q931_help patch')
# py_bsim.lshcosine_print(diffs[5]['q931_help'], weights, name=f'r5 q931_help patch')
# exit(0)

# Then let's find the most [dis]similar patches!

SIMILARITY_OUTPUT_THRESHOLD = 0.0#0.6

# Within each month:
for month, month_diffs in diffs.items():
    print('-' * 30)
    print(f'Comparing diffs for {month}')

    results = []
    for a in month_diffs:
        for b in month_diffs:
            if b < a: continue
            for name1, vec1 in month_diffs[a].items():
                for name2, vec2 in month_diffs[b].items():
                    if name2 < name1: continue
                    if a == b and name1 == name2: continue
                    similarity = py_bsim.lshcosine_similarity(vec1, vec2, weights)
                    confidence = py_bsim.lshcosine_confidence(vec1, vec2, weights)
                    results.append((similarity, confidence, a, name1, b, name2))

    print('Sorting results')
    results.sort(reverse=True)

    for similarity, confidence, a, name1, b, name2 in results:
        print('\n----')
        print(f'{month} r{a} patch for {name1} is similar to r{b} patch for {name2} (similarity={similarity}, confidence={confidence})')
        py_bsim.lshcosine_print(diffs[month][a][name1], weights, name=f'{month} r{a} {name1} patch')
        py_bsim.lshcosine_print(diffs[month][b][name2], weights, name=f'{month} r{b} {name2} patch')

        if similarity < SIMILARITY_OUTPUT_THRESHOLD:
            break

    for similarity, confidence, a, name1, b, name2 in reversed(results):
        print('\n----')
        print(f'{month} r{a} patch for {name1} is dissimilar to r{b} patch for {name2} (similarity={similarity}, confidence={confidence})')
        py_bsim.lshcosine_print(diffs[month][a][name1], weights, name=f'{month} r{a} {name1} patch')
        py_bsim.lshcosine_print(diffs[month][b][name2], weights, name=f'{month} r{b} {name2} patch')

        if similarity > -SIMILARITY_OUTPUT_THRESHOLD:
            break

print()
print('=' * 60)

# Comparing each month's r1:
print("Calculating diffs across each month's r1")
diffs_r1s = {}
for i in range(1, len(MONTHS_AND_REVS)):
    month_a = MONTHS_AND_REVS[i - 1][0]
    month_b = MONTHS_AND_REVS[i][0]
    diffs_r1s[month_b] = {}
    for name in set(functions[month_a][1]) & set(functions[month_b][1]):
        diff = py_bsim.lshcosine_difference(functions[month_a][1][name], functions[month_b][1][name], weights)
        if not py_bsim.lshcosine_is_zero(diff):
            diffs_r1s[month_b][name] = diff

print(f'Diffs per month: { {month: len(diffs_r1s[month]) for month in sorted(diffs_r1s)} }')

print(f'Comparing diffs for r1 of all months')

results = []
for a in diffs_r1s:
    for b in diffs_r1s:
        if b < a: continue
        if a == b: continue  # TEMP
        for name1, vec1 in diffs_r1s[a].items():
            for name2, vec2 in diffs_r1s[b].items():
                if name2 < name1: continue
                if a == b and name1 == name2: continue
                similarity = py_bsim.lshcosine_similarity(vec1, vec2, weights)
                confidence = py_bsim.lshcosine_confidence(vec1, vec2, weights)
                results.append((similarity, confidence, a, name1, b, name2))

print('Sorting results')
results.sort(reverse=True)

with open('similarities_p_c.txt', 'w', encoding='utf-8') as f:
    for similarity, confidence, a, name1, b, name2 in results:
        f.write(f'{similarity} {confidence} {a} {name1} {b} {name2}\n')
raise

for similarity, confidence, a, name1, b, name2 in results:
    # print('\n----')
    print(f'{a} patch for {name1} is similar to {b} patch for {name2} (similarity={similarity}, confidence={confidence})')
    # py_bsim.lshcosine_print(diffs_r1s[a][name1], weights, name=f'{a} {name1} patch')
    # py_bsim.lshcosine_print(diffs_r1s[b][name2], weights, name=f'{b} {name2} patch')

    if similarity < SIMILARITY_OUTPUT_THRESHOLD:
        break

for similarity, confidence, a, name1, b, name2 in reversed(results):
    # print('\n----')
    print(f'{a} patch for {name1} is dissimilar to {b} patch for {name2} (similarity={similarity}, confidence={confidence})')
    # py_bsim.lshcosine_print(diffs_r1s[a][name1], weights, name=f'{a} {name1} patch')
    # py_bsim.lshcosine_print(diffs_r1s[b][name2], weights, name=f'{b} {name2} patch')

    if similarity > -SIMILARITY_OUTPUT_THRESHOLD:
        break


# Additional things to do:
# 1. Analyze and export signatures for more bins. Particularly ones from other AOSP GKI kernel monthly-release series
# 2. Check for functions that are different in reality but have identical signatures (people will ask)
