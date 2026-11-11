# py-bsim

Python reimplementation of BSim's similarity and confidence algorithms.

## Generating function signature XMLs from Ghidra project

You need to generate/export function signatures from a Ghidra project before you can use py-bsim, which you can do using Ghidra's built-in `bsim` command-line tool as shown below.

Below: `/path/to/ghidra/project/directory` should be the path of a .gpr file, without the ".gpr" suffix. For example, if `/home/user/project.gpr` exists, the second argument should be `ghidra:/home/user/project`. Ghidra is very picky about this and has terrible error messages if you get it wrong.

```sh
$ ghidra_11.0.1_PUBLIC/support/./bsim generatesigs ghidra:/path/to/ghidra/project/directory /path/to/output/signature/directory --config=medium_64
```

## Example usage

```py
from pathlib import Path
import py_bsim

# Load weights (XML file included with Ghidra)
weights = py_bsim.BSimWeights.load_from_path(
    Path('ghidra_11.0.1_PUBLIC/Ghidra/Features/BSim/data/lshweights_64.xml'))

# Load signatures dumped from Ghidra project
signatures = py_bsim.BSimSignatureDump.load_from_path(
    Path('/path/to/output/signature/directory/signatures.xml'))
functions = signatures.as_combined_function_dict()

# Calculate self-significance of a function
self_sig = py_bsim.lshcosine_self_significance(functions['example_function_1'], weights)
print(f'example_function_1 self-significance: {self_sig}')

# Calculate similarity between two functions
similarity = py_bsim.lshcosine_similarity(
    functions['example_function_1'],
    functions['example_function_2'],
    weights,
)
print(f'Similarity between example_function_1 and example_function_2: {similarity}')

# Calculate confidence between two functions
confidence = py_bsim.lshcosine_confidence(
    functions['example_function_1'],
    functions['example_function_2'],
    weights,
)
print(f'Confidence between example_function_1 and example_function_2: {similarity}')
```
