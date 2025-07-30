from __future__ import annotations

import importlib
from pathlib import Path
import py_compile
import subprocess
import sys

import py_bsim
import py_bsim_serialization_version


def load_signatures_xml(path: Path) -> py_bsim.BSimSignatureDump:
    return py_bsim.BSimSignatureDump.load_from_path(path)


def load_signatures_py(path: Path) -> py_bsim.BSimSignatureDump:
    # This *should* be thread-safe, with the way our sys.path
    # manipulations are set up

    sys.path.insert(0, str(path.parent))
    try:
        # note: requires py_bsim to be on sys.path at import time
        try:
            mod = importlib.import_module(path.with_suffix('').name)
            return mod.DATA
        except Exception:
            raise ValueError(f'Unable to load {path.name}')
    finally:
        sys.path.remove(str(path.parent))


def save_signatures_py(data: py_bsim.BSimSignatureDump, path: Path) -> None:
    with path.open('w', encoding='utf-8') as f:
        f.write(f"""
try:
    from py_bsim import *
    from py_bsim_serialization_version import *
except ImportError:
    from .py_bsim import *
    from .py_bsim_serialization_version import *

if REIMPL_LIB_VERSION > {py_bsim_serialization_version.REIMPL_LIB_VERSION}:
    raise ValueError(f'py_bsim version too new ({{REIMPL_LIB_VERSION}} > {py_bsim_serialization_version.REIMPL_LIB_VERSION})')

DATA = """)
        f.write(repr(data))

    # Pre-compile to bytecode
    py_compile.compile(str(path))


def load_signatures_xml_cached(path: Path, *, verbose: bool = True) -> py_bsim.BSimSignatureDump:
    if path.stat().st_size < 20_000_000:  # 20 MB
        # Small file -- just load the XML instead of doing the fancy
        # caching stuff
        return load_signatures_xml(path)

    crc = subprocess.check_output(['crc32', str(path)]).decode('ascii').rstrip('\n')

    py_path = path.with_name(path.name + f'_{crc}.py')

    if py_path.is_file():
        try:
            return load_signatures_py(py_path)
        except Exception:
            # .py file is likely out of date -- let's rebuild it
            pass

    if verbose:
        print('Loading from XML and caching as Python source, please wait...')
    data = load_signatures_xml(path)
    save_signatures_py(data, py_path)
    return data
