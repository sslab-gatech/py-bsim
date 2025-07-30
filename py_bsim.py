from __future__ import annotations

import dataclasses
import datetime
import math
from pathlib import Path
from typing import Iterator
try:
    from typing import Self
except ImportError:
    Self = object
import xml.etree.ElementTree as ET


NUM_TF = 64
NUM_IDF = 512


def assert_no_unknown_attributes(elem: ET.Element, known_attributes: set[str] = frozenset()) -> None:
    unknown_attributes = set(elem.attrib.keys()) - known_attributes
    if unknown_attributes:
        raise ValueError(f'unexpected attributes of <{elem.tag}>: {", ".join(unknown_attributes)}') from None


@dataclasses.dataclass
class BSimWeights:
    """Represents <weights> tag"""
    # ref. /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/LSHVectorFactory.java

    # "Settings used to generate weights and lookup hashes"
    settings: int

    # Weight factory: "Container for vector weighting information and score normalization"
    # ref. /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/WeightFactory.java
    scale: float        # "Final scaling to all weights"
    addend: float       # "Final correction to score"
    idf: list[float]    # "Weights associated with (normalized) idf counts"
    tf: list[float]     # "Weights associated with tf (term frequency) counts"
    weight_norm: float  # "Scale to which idf weights are normalized = -log2(probability of 1000th most common hash)"
    prob_flip_0: float  # "Hash flipping probability in causal model, param0"
    prob_flip_1: float  # "Hash flipping probability in causal model, param1"
    prob_diff_0: float  # "Hash addition/removal probability, param0"
    prob_diff_1: float  # "Hash addition/removal probability, param1"

    # IDF lookup: "Container for Inverse Document Frequency (IDF) information"
    # ref. /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/IDFLookup.java
    idf_lookup: dict[int, int]  # {hash: count}

    @classmethod
    def load_from_path(cls, path: Path) -> Self:
        tree = ET.parse(str(path))
        root = tree.getroot()

        if root.tag != 'weights':
            raise ValueError(f'wrong root element name for BSim weights file: "{root.tag}" (expected "weights")')

        assert_no_unknown_attributes(root, {'settings'})

        scale = None
        addend = None
        idf = []
        tf = []
        weight_norm = None
        prob_flip_0 = None
        prob_flip_1 = None
        prob_diff_0 = None
        prob_diff_1 = None
        idf_lookup = {}
        found_idflookup = False

        for child in root:
            if child.tag == 'weightfactory':
                if scale is not None:
                    raise ValueError('multiple <weightfactory> tags in <weights>')

                assert_no_unknown_attributes(child, {'scale', 'addend'})
                scale = float(child.attrib['scale'])
                addend = float(child.attrib['addend'])

                for child_2 in child:
                    assert_no_unknown_attributes(child_2)  # applies to all types

                    if child_2.tag == 'idf':
                        idf.append(float(child_2.text))
                    elif child_2.tag == 'tf':
                        tf.append(float(child_2.text))
                    elif child_2.tag == 'weightnorm':
                        weight_norm = float(child_2.text)
                    elif child_2.tag == 'probflip0':
                        prob_flip_0 = float(child_2.text)
                    elif child_2.tag == 'probflip1':
                        prob_flip_1 = float(child_2.text)
                    elif child_2.tag == 'probdiff0':
                        prob_diff_0 = float(child_2.text)
                    elif child_2.tag == 'probdiff1':
                        prob_diff_1 = float(child_2.text)
                    else:
                        raise ValueError(f'unexpected child of <weightfactory> tag: {child_2.tag}')

            elif child.tag == 'idflookup':
                if found_idflookup:
                    raise ValueError('multiple <idflookup> tags in <weights>')
                found_idflookup = True

                assert_no_unknown_attributes(child, {'size'})
                # we ignore "count", though -- it's redundant

                for child_2 in child:
                    if child_2.tag == 'hash':
                        assert_no_unknown_attributes(child_2, {'count'})
                        count = int(child_2.attrib.get('count', 0), 0)
                        value = int(child_2.text, 0)
                        idf_lookup[value] = count
                    else:
                        raise ValueError(f'unexpected child of <idflookup> tag: {child_2.tag}')

            else:
                raise ValueError(f'unexpected child of <weights> tag: {child.tag}')

        if scale is None:
            raise ValueError('no <weightfactory> tag found in <weights>')

        return cls(
            settings = int(root.attrib.get('settings', '0'), 0),
            scale = scale,
            addend = addend,
            idf = idf,
            tf = tf,
            weight_norm = weight_norm,
            prob_flip_0 = prob_flip_0,
            prob_flip_1 = prob_flip_1,
            prob_diff_0 = prob_diff_0,
            prob_diff_1 = prob_diff_1,
            idf_lookup = idf_lookup,
        )

    def to_xml_str(self) -> str:
        lines = [
            f'<weights settings="{hex(self.settings)}">',
            f'<weightfactory scale="{self.scale}" addend="{self.addend}">',
        ]
        for idf in self.idf:
            lines.append(f' <idf>{idf:.8e}</idf>')
        for tf in self.tf:
            lines.append(f' <tf>{tf:.8e}</tf>')
        lines.extend([
            f' <weightnorm>{self.weight_norm:.8e}</weightnorm>',
            f' <probflip0>{self.prob_flip_0:.8e}</probflip0>',
            f' <probflip1>{self.prob_flip_1:.8e}</probflip1>',
            f' <probdiff0>{self.prob_diff_0:.8e}</probdiff0>',
            f' <probdiff1>{self.prob_diff_1:.8e}</probdiff1>',
            '</weightfactory>',
            f'<idflookup size="{len(self.idf_lookup)}">',
        ])
        for hash, count in self.idf_lookup.items():
            lines.append(f'<hash count="{count}">{hex(hash)}</hash>')
        lines.append('</idflookup>')
        lines.append('</weights>')
        return '\n'.join(lines)

    def to_json(self) -> dict:
        return {
            'settings': self.settings,
            'scale': self.scale,
            'addend': self.addend,
            'idf': self.idf,
            'tf': self.tf,
            'weight_norm': self.weight_norm,
            'prob_flip_0': self.prob_flip_0,
            'prob_flip_1': self.prob_flip_1,
            'prob_diff_0': self.prob_diff_0,
            'prob_diff_1': self.prob_diff_1,
            'idf_lookup': [{'hash': hex(k), 'value': v} for k, v in self.idf_lookup.items()],
        }

    def get_scaled_idf(self, index: int) -> float:
        # /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/WeightFactory.java/WeightFactory.restoreXml()
        return self.idf[index] * (self.scale ** 0.5)

    def get_coeff(self, hash_value: int, tf: int | float) -> float:
        # /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/HashEntry.java/HashEntry.restoreXml() (3-arg overload)
        # /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/WeightFactory.java/WeightFactory.getCoeff()
        # Unlike WeightFactory.getCoeff(), "tf" here is an absolute count, not a 0-based index
        # (this makes it possible to deal with negative tf values)
        # I also adjusted this to properly handle negative and fractional tf values

        def index_tf(idx: int) -> float:
            if idx >= len(self.tf):
                if self.tf[63] == 2.64575131:
                    # This is (almost certainly) the default "64" weights.
                    # I fitted it to a logarithmic curve (R^2=0.999361)
                    # so we can extrapolate:
                    f_x = 0.298465530660736 * math.log(idx) + 1.4197728111609
                    f_x -= 0.010604406  # avoid a discontinuity at the cutoff point
                    return f_x
                else:
                    raise NotImplementedError(f'unable to extrapolate from unknown set of weights')
            else:
                return self.tf[idx]

        def get_coeff_int(tf: int) -> float:
            idf_idx = self.idf_lookup.get(hash_value, 0)
            scaled_idf = self.get_scaled_idf(idf_idx)

            if tf > 0:
                return scaled_idf * index_tf(tf - 1)
            elif tf < 0:
                return scaled_idf * -index_tf(-tf - 1)
            else:
                return 0.0

        if isinstance(tf, int):
            return get_coeff_int(tf)
        else:
            # simple linear interpolation -- maybe improve in the future?
            # it's approximately (?) a logarithmic curve -- maybe
            # automatically do a regression when the class is created
            # and just use that?
            tf_a = math.floor(tf)
            tf_b = math.ceil(tf)
            return get_coeff_int(tf_a) * (tf_b - tf) + get_coeff_int(tf_b) * (tf - tf_a)


@dataclasses.dataclass
class BSimCall:
    """Represents <call> tag"""
    # ref. /Ghidra/Features/BSim/src/main/java/ghidra/features/bsim/query/description/CallgraphEntry.java
    dest: str
    addr: int | None
    local: int | None
    md5: str | None
    name: str | None
    arch: str | None
    compiler: str | None

    @classmethod
    def load(cls, elem: ET.Element) -> Self:
        if elem.tag != 'call':
            raise ValueError(f'wrong element name for BSim call: "{elem.tag}" (expected "call")')

        assert_no_unknown_attributes(elem, {'dest', 'addr', 'local'})
        dest = elem.attrib['dest']
        addr = elem.attrib.get('addr')
        if addr is not None:
            addr = int(addr, 0)
        local = elem.attrib.get('local')
        if local is not None:
            local = int(local, 0)

        md5 = name = arch = compiler = None
        for child in elem:
            # "child.text or ''": etree sets child.text to None for "<tag></tag>" tags :/
            if child.tag == 'md5':
                assert_no_unknown_attributes(child)
                md5 = child.text or ''
            elif child.tag == 'name':
                assert_no_unknown_attributes(child)
                name = child.text or ''
            elif child.tag == 'arch':
                assert_no_unknown_attributes(child)
                arch = child.text or ''
            elif child.tag == 'compiler':
                assert_no_unknown_attributes(child)
                compiler = child.text or ''
            else:
                raise ValueError(f'unexpected child of <call> tag: {child.tag}')

        return cls(
            dest=dest,
            addr=addr,
            local=local,
            md5=md5,
            name=name,
            arch=arch,
            compiler=compiler,
        )

    @classmethod
    def from_json(cls, data: dict) -> Self:
        return cls(
            dest = data['dest'],
            addr = data.get('addr'),
            local = data.get('local'),
            md5 = data.get('md5'),
            name = data.get('name'),
            arch = data.get('arch'),
            compiler = data.get('compiler'),
        )

    def to_xml_str(self) -> str:
        lines = []

        # first line will be filled in later
        if self.md5 is not None:
            lines.append(f'  <md5>{self.md5}</md5>')
        if self.name is not None:
            lines.append(f'  <name>{self.name}</name>')
        if self.arch is not None:
            lines.append(f'  <arch>{self.arch}</arch>')
        if self.compiler is not None:
            lines.append(f'  <compiler>{self.compiler}</compiler>')

        first_line = [f'<call dest="{self.dest}"']
        if self.addr is not None:
            first_line.append(f' addr="{hex(self.addr)}"')
        if self.local is not None:
            first_line.append(f' addr="{hex(self.local)}"')

        if lines:
            first_line.append('>')
            lines.append('</call>')
        else:
            first_line.append('/>')

        lines.insert(0, ''.join(first_line))
        return '\n'.join(lines)

    def to_json(self) -> dict:
        d = {
            'dest': self.dest,
        }
        if self.addr is not None:
            d['addr'] = self.addr
        if self.local is not None:
            d['local'] = self.local
        if self.md5 is not None:
            d['md5'] = self.md5
        if self.name is not None:
            d['name'] = self.name
        if self.arch is not None:
            d['arch'] = self.arch
        if self.compiler is not None:
            d['compiler'] = self.compiler
        return d


HashAndTf = tuple[int, int | float]
Vec = dict[int, int | float]


@dataclasses.dataclass
class BSimFDesc:
    """Represents <fdesc> tag"""
    # ref. /Ghidra/Features/BSim/src/main/java/ghidra/features/bsim/query/description/FunctionDescription.java
    # ref. /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/LSHCosineVector.java
    # ref. /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/HashEntry.java
    # note: tf values in lshcosine_hashes are absolute counts, not subtracted by 1 as in HashEntry.java
    name: str
    addr: int | None
    sigdup: int
    flags: int
    lshcosine_hashes: Vec
    calls: list[BSimCall]

    @classmethod
    def load(cls, elem: ET.Element) -> Self:
        if elem.tag != 'fdesc':
            raise ValueError(f'wrong element name for BSim fdesc: "{elem.tag}" (expected "fdesc")')

        assert_no_unknown_attributes(elem, {'name', 'addr'})
        name = elem.attrib['name']
        addr = elem.attrib.get('addr')
        if addr is not None:
            addr = int(addr, 0)
        sigdup = int(elem.attrib.get('sigdup', 0))

        lshcosine_hashes = {}
        found_lshcosine = False
        calls = []
        flags = 0
        for child in elem:
            if child.tag == 'lshcosine':
                if found_lshcosine:
                    raise ValueError('multiple <lshcosine> tags in <fdesc>')
                found_lshcosine = True

                assert_no_unknown_attributes(child)
                for c2 in child:
                    if c2.tag != 'hash':
                        raise ValueError(f'wrong element name for BSim hash: "{c2.tag}" (expected "hash")')

                    assert_no_unknown_attributes(c2, {'tf'})

                    tf = c2.attrib.get('tf', '1')
                    if '.' in tf:
                        tf = float(tf)
                    else:
                        tf = int(tf, 0)

                    value = int(c2.text, 0)

                    lshcosine_hashes[value] = tf

            elif child.tag == 'call':
                calls.append(BSimCall.load(child))

            elif child.tag == 'flags':
                if flags != 0:
                    raise ValueError('multiple <flags> tags in <fdesc>')

                assert_no_unknown_attributes(child)
                flags = int(child.text, 0)

            else:
                raise ValueError(f'unexpected child of <fdesc> tag: {child.tag}')

        return cls(
            name=name,
            addr=addr,
            sigdup=sigdup,
            lshcosine_hashes=lshcosine_hashes,
            calls=calls,
            flags=flags,
        )

    @classmethod
    def from_json(cls, data: dict) -> Self:
        return cls(
            name = data['name'],
            addr = data.get('addr'),
            sigdup = data['sigdup'],
            flags = data['flags'],
            lshcosine_hashes = {int(k): v for k, v in data['lshcosine_hashes'].items()},
            calls = [BSimCall.from_json(f) for f in data['calls']],
        )

    def to_xml_str(self) -> str:
        first_line = f'<fdesc name="{self.name}"'
        if self.addr is not None:
            first_line += f' addr="{hex(self.addr)}"'
        if self.sigdup != 0:
            first_line += f' sigdup="{self.sigdup}"'
        first_line += '>'

        lines = [first_line]

        if self.lshcosine_hashes:
            lines.append('<lshcosine>')
            for hash, tf in self.lshcosine_hashes.items():
                if isinstance(tf, int) and tf == 1:
                    lines.append(f' <hash>{hex(hash)}</hash>')
                else:
                    lines.append(f' <hash tf="{tf}">{hex(hash)}</hash>')
            lines.append('</lshcosine>')

        for call in self.calls:
            lines.append(call.to_xml_str())

        if self.flags != 0:
            lines.append(f'<flags>{hex(self.flags)}</flags>')

        lines.append('</fdesc>')
        return '\n'.join(lines)

    def to_json(self) -> dict:
        d = {
            'name': self.name,
        }
        if self.addr is not None:
            d['addr'] = self.addr
        d['sigdup'] = self.sigdup
        d['flags'] = self.flags
        d['lshcosine_hashes'] = {str(k): v for k, v in self.lshcosine_hashes.items()}
        d['calls'] = [c.to_json() for c in self.calls]
        return d


VecOrFunc = Vec | BSimFDesc


@dataclasses.dataclass
class BSimExecList:
    """Represents <execlist> tag"""
    # ref. /Ghidra/Features/BSim/src/main/java/ghidra/features/bsim/query/description/DescriptionManager.java
    # ref. /Ghidra/Features/BSim/src/main/java/ghidra/features/bsim/query/description/ExecutableRecord.java
    is_library: bool
    md5: str
    name: str
    arch: str
    compiler: str
    date: datetime.datetime
    repository: str | None
    path: str | None
    contents: list[BSimFDesc]

    @classmethod
    def load(cls, elem: ET.Element) -> Self:
        if elem.tag != 'execlist':
            raise ValueError(f'wrong element name for BSim exec list: "{elem.tag}" (expected "execlist")')

        assert_no_unknown_attributes(elem)

        md5 = name = arch = compiler = date = repository = path = None
        found_exe = False
        contents = []
        for child in elem:
            if child.tag == 'exe':
                if found_exe:
                    raise ValueError('multiple <exe> tags in <execlist>')
                found_exe = True

                assert_no_unknown_attributes(child, {'library'})
                is_library = child.attrib.get('library', 'false') == 'true'

                for child_2 in child:
                    if child_2.tag == 'md5':
                        assert_no_unknown_attributes(child_2)
                        md5 = child_2.text or ''
                    elif child_2.tag == 'name':
                        assert_no_unknown_attributes(child_2)
                        name = child_2.text or ''
                    elif child_2.tag == 'arch':
                        assert_no_unknown_attributes(child_2)
                        arch = child_2.text or ''
                    elif child_2.tag == 'compiler':
                        assert_no_unknown_attributes(child_2)
                        compiler = child_2.text or ''
                    elif child_2.tag == 'date':
                        assert_no_unknown_attributes(child_2, {'millis'})
                        unix = int(child_2.text, 0)
                        millis = int(child_2.attrib.get('millis', 0), 0)
                        date = (datetime.datetime
                            .fromtimestamp(unix)
                            .replace(microsecond=millis*1000))
                    elif child_2.tag == 'repository':
                        assert_no_unknown_attributes(child_2)
                        repository = child_2.text or ''
                    elif child_2.tag == 'path':
                        assert_no_unknown_attributes(child_2)
                        path = child_2.text or ''
                    else:
                        raise ValueError(f'unexpected child of <exe> tag: {child_2.tag}')
            elif child.tag == 'fdesc':
                contents.append(BSimFDesc.load(child))
            else:
                raise ValueError(f'unexpected child of <execlist> tag: {child.tag}')

        return cls(
            is_library=is_library,
            md5=md5,
            name=name,
            arch=arch,
            compiler=compiler,
            date=date,
            repository=repository,
            path=path,
            contents=contents,
        )

    @classmethod
    def from_json(cls, data: dict) -> Self:
        return cls(
            is_library = data['is_library'],
            md5 = data['md5'],
            name = data['name'],
            arch = data['arch'],
            compiler = data['compiler'],
            date = datetime.datetime.fromisoformat(data['date']),
            repository = data.get('repository'),
            path = data.get('path'),
            contents = [BSimFDesc.from_json(f) for f in data['contents']],
        )

    def to_xml_str(self) -> str:
        lines = ['<execlist>']

        if self.is_library:
            lines.append('<exe library="true">')
        else:
            lines.append('<exe>')

        lines.append(f'  <md5>{self.md5}</md5>')
        lines.append(f'  <name>{self.name}</name>')
        lines.append(f'  <arch>{self.arch}</arch>')
        lines.append(f'  <compiler>{self.compiler}</compiler>')
        ts = hex(int(self.date.timestamp()))
        millis = round(self.date.microsecond / 1000)
        # note: ghidra always includes millis attribute, even if 0
        lines.append(f'  <date millis="{hex(millis)}">{ts}</date>')
        if self.repository is not None:
            lines.append(f'  <repository>{self.repository}</repository>')
        if self.path is not None:
            lines.append(f'  <path>{self.path}</path>')

        lines.append('</exe>')

        for f_desc in self.contents:
            lines.append(f_desc.to_xml_str())

        lines.append('</execlist>')
        return '\n'.join(lines)

    def to_json(self) -> dict:
        d = {
            'is_library': self.is_library,
            'md5': self.md5,
            'name': self.name,
            'arch': self.arch,
            'compiler': self.compiler,
            'date': self.date.isoformat(),
        }
        if self.repository is not None:
            d['repository'] = self.repository
        if self.path is not None:
            d['path'] = self.path
        d['contents'] = [f.to_json() for f in self.contents]
        return d


@dataclasses.dataclass
class BSimSignatureDump:
    """Represents <description> tag"""
    # ref. /Ghidra/Features/BSim/src/main/java/ghidra/features/bsim/query/description/DescriptionManager.java
    layout_version: int
    major: int
    minor: int
    settings: int
    contents: list[BSimExecList]

    @classmethod
    def load_from_path(cls, path: Path) -> Self:
        tree = ET.parse(str(path))
        root = tree.getroot()

        if root.tag != 'description':
            raise ValueError(f'wrong root element name for BSim signature dump: "{root.tag}" (expected "description")')

        assert_no_unknown_attributes(root, {'layout_version', 'major', 'minor', 'settings'})

        contents = [BSimExecList.load(execlist) for execlist in root]

        return cls(
            layout_version = int(root.attrib['layout_version'], 0),
            major = int(root.attrib.get('major', 0), 0),
            minor = int(root.attrib.get('minor', 0), 0),
            settings = int(root.attrib.get('settings', 0), 0),
            contents = contents,
        )

    @classmethod
    def from_json(cls, data: dict) -> Self:
        return cls(
            layout_version = data['layout_version'],
            major = data['major'],
            minor = data['minor'],
            settings = data['settings'],
            contents = [BSimExecList.from_json(e) for e in data['contents']],
        )

    def to_xml_str(self) -> str:
        first_line = ['<description']
        first_line.append(f' layout_version="{self.layout_version}"')
        if self.major != 0:
            first_line.append(f' major="{self.major}"')
            first_line.append(f' minor="{self.minor}"')
        if self.settings != 0:
            first_line.append(f' settings="{hex(self.settings)}"')
        first_line.append('>')

        lines = [
            ''.join(first_line),
            *(c.to_xml_str() for c in self.contents),
            '</description>',
        ]
        return '\n'.join(lines)

    def to_json(self) -> dict:
        return {
            'layout_version': self.layout_version,
            'major': self.major,
            'minor': self.minor,
            'settings': self.settings,
            'contents': [c.to_json() for c in self.contents],
        }

    def as_combined_function_dict(self) -> dict[str, BSimFDesc]:
        """
        Create a dictionary mapping function names to BSimFDesc's.
        Functions from all of the BSimExecList's are put together.
        """
        functions = {}
        for exec_list in self.contents:
            for f_desc in exec_list.contents:
                functions[f_desc.name] = f_desc
        return functions


def get_vec(obj: VecOrFunc) -> Vec:
    if isinstance(obj, dict):
        return obj
    return obj.lshcosine_hashes


def lshcosine_length(vec: VecOrFunc, weights: BSimWeights | None) -> float:
    """
    Calculate the Euclidean length of the feature vector or function.

    /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/LSHCosineVector.java/LSHCosineVector.calcLength()
    """
    vec = get_vec(vec)

    length = 0.0
    for hash, tf in vec.items():
        if weights is None:
            length += tf * tf
        else:
            coeff = weights.get_coeff(hash, tf)
            length += coeff * coeff
    return length ** 0.5


def lshcosine_is_zero(vec: VecOrFunc) -> bool:
    """
    Check whether a vector has nonzero length.
    """
    return not any(get_vec(vec).values())


def lshcosine_self_significance(vec: VecOrFunc, weights: BSimWeights) -> float:
    """
    Calculate the feature vector or function's self-significance (equal
    to the confidence of matching it with itself).

    /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/LSHVectorFactory.java/LSHVectorFactory.getSelfSignificance()
    """
    length = lshcosine_length(vec, weights)
    return length * length + weights.addend


def iter_hash_pairs(v1: VecOrFunc, v2: VecOrFunc) -> Iterator[int, int | float | None, int | float | None]:
    """
    Iterator over lshcosine feature-vector hashes from v1 and v2 that
    have matching hash values. Hashes that are only in one
    vector/function or the other are paired with None.
    """
    v1 = get_vec(v1)
    v2 = get_vec(v2)

    v1_set = set(v1)
    v2_set = set(v2)

    for hash_value in v1_set - v2_set:
        yield hash_value, v1[hash_value], None

    for hash_value in v1_set & v2_set:
        yield hash_value, v1[hash_value], v2[hash_value]

    for hash_value in v2_set - v1_set:
        yield hash_value, None, v2[hash_value]


def iter_hash_pairs_mock_nones(v1: VecOrFunc, v2: VecOrFunc) -> Iterator[int, int | float, int | float]:
    """
    Wrapper for iter_hash_pairs() that replaces None's with 0.
    """
    for hash, tf_a, tf_b in iter_hash_pairs(v1, v2):
        yield hash, (tf_a or 0), (tf_b or 0)


def iter_matching_hashes(v1: VecOrFunc, v2: VecOrFunc) -> Iterator[int, int | float, int | float]:
    """
    Iterator over lshcosine feature-vector hashes from v1 and v2 that
    have matching hash values.
    """
    v1 = get_vec(v1)
    v2 = get_vec(v2)

    for hash_value, tf_1 in v1.items():
        tf_2 = v2.get(hash_value)
        if tf_2 is not None:
            yield hash_value, tf_1, tf_2


def lshcosine_similarity(v1: VecOrFunc, v2: VecOrFunc, weights: BSimWeights) -> float:
    """
    Calculate the similarity between two feature vectors or functions.

    /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/LSHCosineVector.java/LSHCosineVector.compare()
    """
    # Algorithm note: the reason why considering only matching hashes is
    # OK is because the summation terms for all the other hashes would
    # be either 0*x or x*0 (or 0*0) for some x.

    # Note 2: I modified it to handle negative coefficients properly,
    # which the algorithm never has to deal with in its original
    # setting.

    res = 0.0
    for hash_value, tf_1, tf_2 in iter_matching_hashes(v1, v2):
        same_sign = (tf_1 > 0) == (tf_2 > 0)
        if abs(tf_1) < abs(tf_2):
            w1 = weights.get_coeff(hash_value, tf_1)
            res += w1 * w1 * (1 if same_sign else -1)
        else:
            w2 = weights.get_coeff(hash_value, tf_2)
            res += w2 * w2 * (1 if same_sign else -1)

    res /= lshcosine_length(v1, weights) * lshcosine_length(v2, weights)

    return res


def _lshcosine_confidence_inner(v1: VecOrFunc, v2: VecOrFunc, weights: BSimWeights) -> float:
    """
    Calculate the confidence (also referred to as "significance" in
    Ghidra's code) of matching two functions.

    /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/LSHVectorFactory.java/LSHVectorFactory.calculateSignificance()
    + /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/LSHCosineVector.java/LSHCosineVector.compare()
    + /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/VectorCompare.java/VectorCompare.fillOut()
    + /Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/WeightFactory.java/WeightFactory.updateNorms()
    """
    # Adjustments have been made to properly handle negative tf values
    v1 = get_vec(v1)
    v2 = get_vec(v2)

    dot_product = 0.0
    for hash_value, tf_1, tf_2 in iter_matching_hashes(v1, v2):
        same_sign = (tf_1 > 0) == (tf_2 > 0)
        if abs(tf_1) < abs(tf_2):
            w1 = weights.get_coeff(hash_value, tf_1)
            dot_product += w1 * w1 * (1 if same_sign else -1)
        else:
            w2 = weights.get_coeff(hash_value, tf_2)
            dot_product += w2 * w2 * (1 if same_sign else -1)

    a_abs_count = sum(abs(tf) for tf in v1.values())
    b_abs_count = sum(abs(tf) for tf in v2.values())
    max_ = max(a_abs_count, b_abs_count)

    diff = abs(sum(tf for tf in v1.values()) - sum(tf for tf in v2.values()))

    num_flip = 0
    for hash_value, tf_1, tf_2 in iter_hash_pairs_mock_nones(v1, v2):
        if a_abs_count > b_abs_count:  # "a is larger"
            num_flip += max(0, abs(tf_2) - abs(tf_1))  # terms unique to b
        else:
            num_flip += max(0, abs(tf_1) - abs(tf_2))  # terms unique to a

    prob_flip_0_norm = weights.prob_flip_0 * weights.scale
    prob_flip_1_norm = weights.prob_flip_1 * weights.scale
    prob_diff_0_norm = weights.prob_diff_0 * weights.scale
    prob_diff_1_norm = weights.prob_diff_1 * weights.scale

    return (abs(dot_product)
        - num_flip * (prob_flip_0_norm + prob_flip_1_norm / max_)
        - diff * (prob_diff_0_norm + prob_diff_1_norm / max_)
        + weights.addend)


def lshcosine_confidence(v1: VecOrFunc, v2: VecOrFunc, weights: BSimWeights) -> float:
    """
    Calculate the confidence (also referred to as "significance" in
    Ghidra's code) of matching two functions.
    """
    # We're either confident about them being similar (positive
    # similarity), or confident about them being opposites (negative
    # similarity).
    if lshcosine_similarity(v1, v2, weights) >= 0:
        return _lshcosine_confidence_inner(v1, v2, weights)
    else:
        negative_v2 = {hash: -tf for hash, tf in get_vec(v2).items()}
        return _lshcosine_confidence_inner(v1, negative_v2, weights)


def lshcosine_difference(v1: VecOrFunc, v2: Vec, weights: BSimWeights) -> Vec:
    """
    Calculate the vector difference between two functions: v1 - v2
    """
    new_vec = {}

    for hash_value, tf_1, tf_2 in iter_hash_pairs_mock_nones(v1, v2):
        if tf_1 != tf_2:
            new_vec[hash_value] = tf_1 - tf_2

    return new_vec


def lshcosine_print(v: VecOrFunc, weights: BSimWeights | None = None, *, name: str | None = None, columns: int = 3) -> None:
    """
    Pretty-print a vector
    """
    if name is None:
        if hasattr(v, 'name'):
            name = v.name
        else:
            name = 'vector'
    v = get_vec(v)

    notes = [f'{len(v)} dimensions']
    if weights is not None:
        notes.append(f'length {lshcosine_length(v, weights):0.4f}')
        notes.append(f'self-sig. {lshcosine_self_significance(v, weights):0.4f}')

    print(f'{name} ({", ".join(notes)}) <')

    elements = []
    for hash, tf in sorted(v.items()):
        if weights is None:
            elements.append(f'0x{hash:08x}: {tf},')
        else:
            elements.append(f'0x{hash:08x}: {tf} (coeff. {weights.get_coeff(hash, tf):0.4f}),')

    num_columns = columns

    while len(elements) % num_columns != 0:
        elements.append('')

    elems_per_column = len(elements) // columns
    column_width = max(len(e) for e in elements)

    for i in range(elems_per_column):
        these_elems = elements[i : : elems_per_column]
        joined = '  |  '.join(e.ljust(column_width) for e in these_elems)
        print(f'  {joined.rstrip()}')

    print('>')
