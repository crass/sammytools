#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Add subtitle files in the same directory as videos containing the subtitles
# with the same name, but apropriate subtitle extension.
# Copyright 2011 crass <crass@berlios.de>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#   2. Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#   3. The name of the author may not be used to endorse or promote products
#      derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
# EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import sys
import os
import struct
import cStringIO as StringIO
import zlib

from Crypto.Util import strxor
from Crypto.Cipher import AES

MODEL_KEYS = {
    'C6900': '\xEA\xEA\x51\x2D\xA9\x1F\x87\xE1\xC4\x15\x4C\x3E\xDB\x7A\xAD\xB8',
    'C5500': '\x48\x77\x81\x5A\x17\x51\x14\x80\xF9\xD1\x5B\xDF\xE3\x0C\x21\x63',
}

class RUFSubfile(object):
    pass

class RUFHeader(object):
    commonhdr_fmt = "6s4s2s32s8s32s"
    subfile_fmt = 'III'
    model_fmts = {
        'C6900': '31s5s',
        'C5500': '33s5s',
    }
    headersz = 0x800
    subfilenumpos = 0xc1
    subfilehdrstart = 0x120
    subfilehdrsz = 0x40
    
    fileparts = [
        "exe.img",              #  1   ??? stl.restore ???
        "Image",                #  2   fsrrestore /dev/bml0/{5|7}  Image
        "rootfs.img",           #  3   fsrrestore /dev/bml0/{6|8}  rootfs.img
        "appdata.img",          #  4   ??? stl.restore ???
        "loader",               #  5   ??? BR/DVD/CD disc drive firmware ???
        "onboot",               #  6   fsrbootwriter /dev/bml0/c   onboot.bin
        "boot_image.raw",       #  7   fsrrestore /dev/bml0/20     boot_image.raw
        "bootsound",            #  8   fsrrestore /dev/bml0/22     BootSound
        "cmac.bin",             #  9   fsrrestore /dev/bml0/{9|10} cmac.bin
        "key.bin",              # 10   fsrrestore /dev/bml0/11     key.bin
    ]
    
    @staticmethod
    def parse(fileobj):
        rufh = RUFHeader()
        commonhdr_fmt = RUFHeader.commonhdr_fmt
        model_fmts = RUFHeader.model_fmts
        subfile_fmt = RUFHeader.subfile_fmt
        
        rufh.ftype, rufh.endian, rufh.raw1, rufh.fwdate, rufh.manufacturer, \
            rufh.model = struct.unpack(commonhdr_fmt,
                                fileobj.read(struct.calcsize(commonhdr_fmt)))
        
        rufh.model = rufh.model.rstrip('\x00')
        rufh.endian = rufh.endian.rstrip('\x00')
        
        # Make sure integers are read with the correct endianness
        e='<'
        if rufh.endian == 'BE':
            # Big Endian
            e = '>'
        
        model_fmt = model_fmts[rufh.model]
        rufh.raw2, rufh.raw3 \
            = struct.unpack(e+model_fmt, fileobj.read(struct.calcsize(model_fmt)))
        rufh.size, = struct.unpack(e+'I', fileobj.read(4))
        
        # Get the count of subfiles
        fileobj.seek(RUFHeader.subfilenumpos)
        rufh.subfile_cnt = ord(fileobj.read(1))
        
        fileobj.seek(RUFHeader.subfilehdrstart)
        rufh.subfiles = []
        subfileleft = rufh.subfile_cnt
        while subfileleft:
            subfilehdr = fileobj.read(RUFHeader.subfilehdrsz)
            rs = RUFSubfile()
            #~ print '>>', repr(subfilehdr[:16])
            rs.num, rs.size, rs.crc32 \
                = struct.unpack(e+subfile_fmt, subfilehdr[:12])
            if rs.num > 0:
                #~ print 'Got part num:', rs.num, rs.size, rs.crc32
                rs.name = RUFHeader.fileparts[rs.num-1]
                rufh.subfiles.append(rs)
                subfileleft -= 1
        
        fileobj.seek(0, 2)
        filesz = fileobj.tell()
        fileobj.seek(0)
        
        # Check to make sure the header makes sense
        if sum([sf.size for sf in rufh.subfiles]) + RUFHeader.subfilehdrstart > filesz:
            raise ValueError("Wrong header format. Aborting")
        
        fileobj.seek(0)
        return rufh


class RUFFile(object):
    def __init__(self, file):
        if isinstance(file, basestring):
            file = open(file, 'rb')
        self.file = file
        self.rufh = RUFHeader.parse(file)
        self.decrypted = None
    
    def decrypt(self, blocksz=64*1024):
        ""
        file = self.file
        rufh = self.rufh
        outfile = StringIO.StringIO()
        
        file.seek(0, 2)
        filesz = file.tell()
        file.seek(0)
        
        print "Decrypting firmware file (%d) ..."%filesz,
        sys.stdout.flush()
        
        # Write out unencrypted header
        outfile.write(file.read(rufh.headersz))
        
        assert (rufh.size%AES.block_size) == 0, 'Encrypted size must be a multiple of cipher block size'
        # Decrypt and write
        aes = AES.new(MODEL_KEYS[rufh.model], AES.MODE_CBC, IV='\x00'*AES.block_size)
        outfile.write(aes.decrypt(file.read(rufh.size)))
        
        # Read the rest of the file and copy directly into outfile
        outfile.write(file.read())
        
        print "Done"
        
        outfile.seek(0)
        self.decrypted = outfile
        return outfile
    
    def extract(self, dirpath):
        " Extract file parts "
        if not self.decrypted:
            self.decrypt()
        file = self.decrypted
        rufh = self.rufh
        file.seek(rufh.headersz)
        for subfile in rufh.subfiles:
            print 'Writing part: %s (%s)'%(subfile.name, subfile.size)
            partpath = os.path.join(dirpath, '%02d.%s'%(subfile.num, subfile.name))
            partfile = open(partpath, 'wb')
            partdata = file.read(subfile.size)
            # validate crc
            #~ crc = zlib.crc32(partdata)
            #~ adler = zlib.adler32(partdata)
            #~ print "CRC:", subfile.crc32, crc, adler
            partfile.write(partdata)


def main(argv):
    for path in argv:
        try:
            basepath, ext = os.path.splitext(path)
            if not os.path.isdir(basepath):
                os.makedirs(basepath)
            RUFFile(path).extract(basepath)
        except Exception, e:
            print "Failed to extract %s: %s"%(path, str(e))
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    main(sys.argv[1:])

