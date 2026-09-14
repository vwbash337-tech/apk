import struct, sys
from capstone import *
import os
SO=os.path.join(os.path.dirname(os.path.abspath(__file__)),'apk_extracted','lib','arm64-v8a','libtopfollow.so')
b=open(SO,'rb').read()
md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True
def dis(off, n, label=None):
    print('=== %s @ 0x%x ===' % (label or 'func', off))
    for i in md.disasm(b[off:off+n*4], off):
        print('  0x%06x  %-9s %s' % (i.address, i.mnemonic, i.op_str))
if __name__=='__main__':
    off=int(sys.argv[1],16); n=int(sys.argv[2]) if len(sys.argv)>2 else 30
    dis(off,n,sys.argv[3] if len(sys.argv)>3 else None)
