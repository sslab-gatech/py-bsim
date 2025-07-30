from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
import py_compile
import subprocess
import sys
import time
from typing import Any

import py_bsim
import py_bsim_serialization

SHOW_CMDS = False

MAIN_REPO_DIR = Path('../linux')
SIGNATURES_DIR = Path('../bsim-linux-dataset/bsim_signatures_symlinks')

JSONL_CONTROL_GROUP = Path('../bsim-linux-dataset/noncve-commitPack2.jsonl')
JSONL_CVE_INTRODUCE_GROUP = Path('../kernel-commitPack/cve-introduce-commitPack.jsonl')
JSONL_CVE_FIX_GROUP = Path('../kernel-commitPack/cve-commitPack.jsonl')

assert JSONL_CONTROL_GROUP.is_file()
assert JSONL_CVE_INTRODUCE_GROUP.is_file()
assert JSONL_CVE_FIX_GROUP.is_file()


def get_subprocess_output(*args, **kwargs) -> Union[str, bytes]:
    if SHOW_CMDS:
        if 'env' in kwargs:
            print(args[0], kwargs['env'])
        else:
            print(args[0])
    return subprocess.check_output(*args, **kwargs)

def get_git_output(repo: Path, *args, **kwargs) -> str:
    args = [['git'] + args[0], *args[1:]]
    kwargs = dict(kwargs)
    if 'encoding' not in kwargs:
        kwargs['encoding'] = 'utf-8'
    return get_subprocess_output(*args, cwd=repo, **kwargs)

def git_get_previous_commit_hash(repo: Path, commit_hash: Optional[GitHash] = None, *args, **kwargs) -> GitHash:
    # If commit is None, uses the currently checked-out commit
    if commit_hash is None:
        which = 'HEAD^1'
    else:
        which = commit_hash + '^1'

    return get_git_output(repo, ['show', '-s', '--format=%H', which]).strip()


def diff_signatures_dict(
    weights: py_bsim.BSimWeights,
    before: dict[str, py_bsim.BSimFDesc],
    after: dict[str, py_bsim.BSimFDesc],
) -> dict[str, py_bsim.BSimFDesc]:
    # TODO: currently ignores added/removed funcs. Account for that?
    diffs = {}
    for name in set(before) & set(after):
        diff = py_bsim.lshcosine_difference(after[name], before[name], weights)
        if not py_bsim.lshcosine_is_zero(diff):
            diffs[name] = diff
    return diffs


def get_diffs_from_jsonl(weights: py_bsim.BSimWeights, jsonl_path: Path):
    with jsonl_path.open('r', encoding='utf-8') as f:
        for line in f:
            line_j = json.loads(line)
            commit_hash = line_j['commit']
            try:
                prev_commit_hash = git_get_previous_commit_hash(MAIN_REPO_DIR, commit_hash)
            except subprocess.CalledProcessError:
                print('Unable to get previous commit hash -- skipping')
                continue
            rel_file_path = line_j['new_file']

            rel_file_path_o = '.'.join(rel_file_path.split('.')[:-1]) + '.o'
            filename_xml = rel_file_path_o.split('/')[-1][:-2] + '.xml'

            signatures_before_fp = SIGNATURES_DIR / f'{prev_commit_hash}_{filename_xml}'
            signatures_after_fp = SIGNATURES_DIR / f'{commit_hash}_{filename_xml}'

            if not signatures_before_fp.exists() or not signatures_after_fp.exists():
                print('Missing one or both signatures -- skipping')
                continue

            signatures_before = py_bsim_serialization.load_signatures_xml_cached(signatures_before_fp).as_combined_function_dict()
            signatures_after = py_bsim_serialization.load_signatures_xml_cached(signatures_after_fp).as_combined_function_dict()
            # for ss in signatures_before.values():
            #     for h in ss.lshcosine_hashes.keys():
            #         all_hashes.add(h)
            # for ss in signatures_after.values():
            #     for h in ss.lshcosine_hashes.keys():
            #         all_hashes.add(h)
            signatures_diff = diff_signatures_dict(weights, signatures_before, signatures_after)
            # if commit_hash.startswith('635d9398178659d8ddba79dd061f9451cec0b4d1'):
            #     print('YYYYYYY', signatures_before)
            #     print('ZZZZZZZ', signatures_after)

            yield line_j, signatures_diff


def analyze_dataset(
    weights: py_bsim.BSimWeights,
    jsonl_path: Path,
) -> dict[str, Any]:
    freqs = {}
    diffs_count = 0
    total_tfs = 0
    total_tfs_abs = 0
    specific_counts = {}  # {term: {commit: {func_name: tf}}}
    commit_to_diff = {}
    for line_j, signatures_diff in get_diffs_from_jsonl(weights, jsonl_path):
        commit_hash = line_j['commit']
        commit_to_diff[commit_hash] = signatures_diff
        # if commit_hash.startswith('635d9398178659d8ddba79dd061f9451cec0b4d1'):
        #     print('XXXXX', signatures_diff)
        #     raise
        diffs_count += 1
        for func_name, vec in signatures_diff.items():
            for hash, tf in vec.items():
                total_tfs += tf
                total_tfs_abs += abs(tf)

                specific_counts.setdefault(hash, {})
                specific_counts[hash].setdefault(commit_hash, {})
                specific_counts[hash][commit_hash][func_name] = tf

                freqs.setdefault(hash, 0)
                freqs[hash] += tf  # TODO: also try with abs()?

    return {
        'commit_to_diff': commit_to_diff,
        'total_diffs': diffs_count,
        'total_tfs': total_tfs,
        'total_tfs_abs': total_tfs_abs,
        'sum_vec': freqs,
        'specific_counts': specific_counts,
    }


def scale_vec(vec: Vec, factor: float) -> Vec:
    return {hash: tf * factor for hash, tf in vec.items()}


def normalize(vec: Vec, weights: py_bsim.BSimWeights | None = None, *, target_length: float = 1.0) -> Vec:
    length = py_bsim.lshcosine_length(vec, weights)

    if weights is None:
        return scale_vec(vec, target_length / length)

    else:
        # Unfortunately that doesn't work if we have weights, since
        # weighted lengths don't scale linearly with tfs.
        # I think the best thing to do here is a sort of bisection
        # to get an approximation.
        EPSILON = 1e-10

        if length < target_length:
            factor_low = factor_high = 1
            length_high = length
            while length_high < target_length:
                factor_low = factor_high
                factor_high *= 2
                length_high = py_bsim.lshcosine_length(
                    scale_vec(vec, factor_high),
                    weights,
                )
            del length_high

        elif length > target_length:
            factor_low = factor_high = 1
            length_low = length
            while length_low > target_length:
                factor_high = factor_low
                factor_low /= 2
                length_low = py_bsim.lshcosine_length(
                    scale_vec(vec, factor_low),
                    weights,
                )
            del length_low

        else:
            return vec.copy()

        factor_mid = (factor_low + factor_high) / 2

        while factor_low < factor_high and abs(factor_high - factor_low) > EPSILON:
            factor_mid = (factor_low + factor_high) / 2
            vec_mid = scale_vec(vec, factor_mid)
            length_mid = py_bsim.lshcosine_length(vec_mid, weights)
            if length_mid < target_length:
                factor_low = factor_mid
            elif length_mid > target_length:
                factor_high = factor_mid
            else:
                return vec_mid

        return scale_vec(vec, factor_mid)


weights = py_bsim.BSimWeights.load_from_path('../ghidra/ghidra_11.0.1_PUBLIC/Ghidra/Features/BSim/data/lshweights_64.xml')

# temporarily removed for speed
print('Analyzing control group...')
control_data = analyze_dataset(weights, JSONL_CONTROL_GROUP)

print('Analyzing CVE-introduce group...')
cve_introduce_data = analyze_dataset(weights, JSONL_CVE_INTRODUCE_GROUP)

print('Analyzing CVE-fix group...')
cve_fix_data = analyze_dataset(weights, JSONL_CVE_FIX_GROUP)

def perform_90_10_stuff(commit_to_diff):
    import random
    all_probabilities = []
    for trial in range(10):
        print(f'Trial {trial}')
        # Randomly split the data 10 ways
        NUM_GROUPS = 10
        r = random.Random(1234567 * trial)
        groups = [{} for _ in range(NUM_GROUPS)]
        for commit_hash, commit_contents in commit_to_diff.items():
            feature_diff = {}
            for func_name, hash_to_tf in commit_contents.items():
                for hash, tf in hash_to_tf.items():
                    feature_diff.setdefault(hash, 0)
                    feature_diff[hash] = feature_diff[hash] + tf
            group_num = r.randrange(NUM_GROUPS)
            groups[group_num][commit_hash] = feature_diff

        probabilities = []
        for test_set_i in range(NUM_GROUPS):
            trained_hashes = set()
            test_hashes = set()
            for i, group in enumerate(groups):
                for diff in group.values():
                    # print('XXXXXX', diff.keys())
                    # TODO: this assumes that training on a hash is a binary yes/no thing
                    if i == test_set_i:
                        test_hashes |= set(diff.keys())
                    else:
                        trained_hashes |= set(diff.keys())

            # What percentage of the test hashes are in the training data?
            pct = len(test_hashes & trained_hashes) / len(test_hashes)
            probabilities.append(pct)

        print(f'Training-set inclusion probability for each group: {probabilities} -> avg is {sum(probabilities) / NUM_GROUPS}')
        all_probabilities.extend(probabilities)

    print(f'Overall average from all {NUM_GROUPS} trials is {sum(all_probabilities) / len(all_probabilities)}')


print('----')
print('Performing 90/10 data split analysis:')

print(f'\n1. CONTROL (size: {len(control_data["commit_to_diff"])} commits)')
perform_90_10_stuff(control_data['commit_to_diff'])
print(f'\n2. INTRODUCE (size: {len(cve_introduce_data["commit_to_diff"])} commits)')
perform_90_10_stuff(cve_introduce_data['commit_to_diff'])
print(f'\n3. FIX (size: {len(cve_fix_data["commit_to_diff"])} commits)')
perform_90_10_stuff(cve_fix_data['commit_to_diff'])
combined = {**control_data['commit_to_diff'], **cve_introduce_data['commit_to_diff'], **cve_fix_data['commit_to_diff']}
print(f'\n4. ALL (size: {len(combined)} commits)')
perform_90_10_stuff(combined)






def summarize(title: str, data: dict[str, Any]) -> None:
    print(f'Important statistics for {title} group:')
    print(f'  - Total usable diffs (commits): {data["total_diffs"]}')
    print(f'  - Total tfs: {data["total_tfs"]}')
    print(f'  - Total tfs (absolute values): {data["total_tfs_abs"]}')
    print(f'  - Average tf count per commit: {data["total_tfs"] / data["total_diffs"]}')
    print(f'  - Average tf count per commit (absolute values): {data["total_tfs_abs"] / data["total_diffs"]}')
    print(f'  - (Weighted) length of raw sum vector: {py_bsim.lshcosine_length(data["sum_vec"], weights)}')
    print(f'  - (Weighted) length of raw sum vector / num diffs: {py_bsim.lshcosine_length(scale_vec(data["sum_vec"], 1/data["total_diffs"]), weights)}')

summarize('control', control_data)
summarize('cve-introduce', cve_introduce_data)
summarize('cve-fix', cve_fix_data)

# {
#     'total_diffs': diffs_count,
#     'total_tfs': total_tfs,
#     'avg_tfs_per_diff': total_tfs / diffs_count,
#     'vec': freqs,
#     'specific_counts': specific_counts,
# }

# COUNT_SPECIFICALLY = 0xab6831d3
# COUNT_SPECIFICALLY = 0x5197f553

print('Normalizing...')
control_vec_norm = normalize(control_data['sum_vec'], weights)
cve_introduce_vec_norm = normalize(cve_introduce_data['sum_vec'], weights)
cve_fix_vec_norm = normalize(cve_fix_data['sum_vec'], weights)
# control_vec_norm = control_data['sum_vec']
# cve_introduce_vec_norm = cve_introduce_data['sum_vec']
# cve_fix_vec_norm = cve_fix_data['sum_vec']

# print(f'Control-group average length (default weights): {py_bsim.lshcosine_length(control_vec_norm, weights)}')
# print(f'CVE-introduce group average length (default weights): {py_bsim.lshcosine_length(cve_introduce_vec_norm, weights)}')
# print(f'CVE-fix group average length (default weights): {py_bsim.lshcosine_length(cve_fix_vec_norm, weights)}')

for title, specific_counts in [
    ('control', control_specific_counts),
    ('introduce', cve_introduce_specific_counts),
    ('fix', cve_fix_specific_counts),
]:
    # structure of specific_counts: {commit_hash: {func_name: tf}}
    print(f'Individual counts for {COUNT_SPECIFICALLY:#08x} in {title} group:')
    pairs = list(specific_counts.items())
    pairs.sort(key=lambda pair: sum(pair[1].values()))
    for commit_hash, commit_info in pairs:
        commit_info = list(commit_info.items())
        commit_info.sort(key=lambda pair: pair[1])
        for func_name, tf in commit_info:
            print(f'{title} {commit_hash}: {func_name:<40} has {tf} of {COUNT_SPECIFICALLY:#08x}')

for title, group_vec in [
    ('introduce', cve_introduce_vec_norm),
    ('fix', cve_fix_vec_norm),
]:
    tf_diff_pairs = []
    for hash, cve_tf in group_vec.items():
        control_tf = control_vec_norm.get(hash, 0)
        tf_diff_pairs.append((hash, cve_tf, control_tf))
    tf_diff_pairs.sort(key=(lambda x: x[1] - x[2]), reverse=True)

    print(f'Distribution differences between {title} and control groups (after normalization):')

    for i, (hash, cve_tf, control_tf) in enumerate(tf_diff_pairs):
        print(f'{hash:08x}: {cve_tf} - {control_tf} = {cve_tf - control_tf}')
        if i > 50: break

    print('...')

    for i, (hash, cve_tf, control_tf) in enumerate(tf_diff_pairs):
        if i < len(tf_diff_pairs) - 50: continue
        print(f'{hash:08x}: {cve_tf} - {control_tf} = {cve_tf - control_tf}')
