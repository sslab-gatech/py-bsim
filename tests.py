import py_bsim


WEIGHTS_PATH = '../ghidra/ghidra_11.0.1_PUBLIC/Ghidra/Features/BSim/data/lshweights_64.xml'
SIGS_PATH = '../bsim-android-dataset/bsim_signatures/sigs_e2190c2e30e695302e2a488244fd3269'

def assert_eq(a, b):
    if a != b:
        raise ValueError(f'{a} (actual) != {b} (expected)')


print('Loading weights...')
weights = py_bsim.BSimWeights.load_from_path(WEIGHTS_PATH)
# print(weights.to_xml_str())
# exit()

print('Loading signatures...')
sigs = py_bsim.BSimSignatureDump.load_from_path(SIGS_PATH)
# print(sigs.to_xml_str())
# exit()

print('Restructing as dict...')
functions = sigs.as_combined_function_dict()

# Self-significance tests
print('Testing self-significance...')
assert_eq(py_bsim.lshcosine_self_significance(functions['COMPRESS_MAPPING'], weights), 11.766555476324132)
assert_eq(py_bsim.lshcosine_self_significance(functions['BIT_initDStream'], weights), 147.00522470493394)

# Similarity tests
print('Testing similarity...')
assert_eq(py_bsim.lshcosine_similarity(functions['COMPRESS_MAPPING'], functions['COMPRESS_MAPPING'], weights), 1.0)
assert_eq(py_bsim.lshcosine_similarity(functions['COMPRESS_MAPPING'], functions['ovl_workdir'], weights), 0.8615243433611237)
assert_eq(py_bsim.lshcosine_similarity(functions['COMPRESS_MAPPING'], functions['snd_soc_dapm_kcontrol_dapm'], weights), 0.7840986774964732)
assert_eq(py_bsim.lshcosine_similarity(functions['BIT_initDStream'], functions['BIT_initDStream'], weights), 1.0)
assert_eq(py_bsim.lshcosine_similarity(functions['BIT_initDStream'], functions['HUF_decompress1X1_usingDTable_internal'], weights), 0.46419954122116786)
assert_eq(py_bsim.lshcosine_similarity(functions['BIT_initDStream'], functions['HUF_decompress1X2_usingDTable_internal'], weights), 0.41151591014056754)
assert_eq(py_bsim.lshcosine_similarity(functions['BIT_initDStream'], functions['FSE_decompress_usingDTable'], weights), 0.25350382392839893)

# Confidence tests
print('Testing confidence...')
assert_eq(py_bsim.lshcosine_confidence(functions['COMPRESS_MAPPING'], functions['COMPRESS_MAPPING'], weights), 11.766555476324132)                      # dnf: 0 0
assert_eq(py_bsim.lshcosine_confidence(functions['COMPRESS_MAPPING'], functions['ovl_workdir'], weights), 11.286860716852985)                           # dnf: 2 0
assert_eq(py_bsim.lshcosine_confidence(functions['COMPRESS_MAPPING'], functions['snd_soc_dapm_kcontrol_dapm'], weights), 10.936149197284356)            # dnf: 4 0
assert_eq(py_bsim.lshcosine_confidence(functions['BIT_initDStream'], functions['BIT_initDStream'], weights), 147.00522470493394)                        # dnf: 0 0
assert_eq(py_bsim.lshcosine_confidence(functions['BIT_initDStream'], functions['HUF_decompress1X1_usingDTable_internal'], weights), 84.07448376450968)  # dnf: 140 36
assert_eq(py_bsim.lshcosine_confidence(functions['BIT_initDStream'], functions['HUF_decompress1X2_usingDTable_internal'], weights), 76.55292510245681)  # dnf: 234 36
assert_eq(py_bsim.lshcosine_confidence(functions['BIT_initDStream'], functions['FSE_decompress_usingDTable'], weights), 24.00822054119384)              # dnf: 904 30

print('All tests passed!')
