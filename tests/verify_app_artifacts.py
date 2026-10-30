"""Inspect disposable official App ASARs without executing or modifying the application."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('asar',type=Path,nargs='+')
parser.add_argument('--previous',type=Path)
args=parser.parse_args()
pinned=json.loads((root/'tests/upstream-versions.json').read_text())
def read(path):
    data=path.read_bytes()
    assert struct.unpack_from('<I',data)[0]==4,'Invalid ASAR'
    size=struct.unpack_from('<I',data,4)[0]+8
    header=json.loads(data[16:16+struct.unpack_from('<I',data,12)[0]])
    def walk(node,prefix=''):
        for name,value in node.get('files',{}).items():
            name=prefix+name
            if 'files' in value: yield from walk(value,name+'/')
            elif 'offset' in value:
                start=size+int(value['offset']); end=start+value['size']
                assert size<=start<=end<=len(data),name
                yield name,data[start:end]
    return data,dict(walk(header))
for path in args.asar:
    data,entries=read(path)
    assert hashlib.sha256(data).hexdigest()==pinned['app_asar_sha256'],path
    package=json.loads(entries['package.json'])
    assert package['name']=='antigravity' and package['version']==pinned['app']
    assert package['main'] in entries
    if args.previous:
        _,previous=read(args.previous)
        changed=[name for name in entries.keys()|previous.keys() if entries.get(name)!=previous.get(name)]
        assert changed==['package.json'],changed
        print('PASS: all archived App code is unchanged from previous version; package.json only')
    print('PASS: official App',pinned['app'],'ASAR hash, version, entry bounds and main entry:',path)
