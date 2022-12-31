#encoding = utf-8
from __future__ import annotations
import os, random, shutil
import struct, subprocess

def to_int(bs):
    return (int.from_bytes(bs, byteorder='little'))

def little_endian_to_float(bs):
    return struct.unpack("<f", bs)[0]

def little_endian_to_int(bs):
    return int.from_bytes(bs, byteorder='little')

def create_dir(dirpath):
	if not os.path.exists(dirpath):
		os.makedirs(dirpath)

def read_header(fp):
	Magic = fp.read(4)
	if list(Magic) == [68, 65, 84, 0]:
		FileCount = little_endian_to_int(fp.read(4))
		FileTableOffset = little_endian_to_int(fp.read(4))
		ExtensionTableOffset = little_endian_to_int(fp.read(4))
		NameTableOffset = little_endian_to_int(fp.read(4))
		SizeTableOffset = little_endian_to_int(fp.read(4))
		hashMapOffset = little_endian_to_int(fp.read(4))
		print(
'''FileCount: %08x
FileTableOffset: %08x
ExtensionTableOffset:%08x
NameTableOffset:%08x
SizeTableOffset:%08x
hashMapOffset:%08x
'''%
			(FileCount, FileTableOffset, ExtensionTableOffset,NameTableOffset,SizeTableOffset,hashMapOffset)
		)
		return (FileCount, FileTableOffset, ExtensionTableOffset,NameTableOffset,SizeTableOffset,hashMapOffset)
	else:
		print('[-] error magic number detected')
		return False

def get_fileinfo(fp, index, FileTableOffset, ExtensionTableOffset, NameTableOffset, SizeTableOffset):
	fp.seek(FileTableOffset + index * 4)
	FileOffset = little_endian_to_int(fp.read(4))
	fp.seek(ExtensionTableOffset + index * 4)
	Extension = fp.read(4).decode('utf-8')
	fp.seek(SizeTableOffset + index * 4)
	Size = little_endian_to_int(fp.read(4))
	fp.seek(NameTableOffset)
	FilenameAlignment = little_endian_to_int(fp.read(4))
	i = 0
	while i < index:
		if list(fp.read(FilenameAlignment))[FilenameAlignment-1] == 0:
			i += 1
	Filename = fp.read(256).split(b'\x00')[0].decode('ascii')
	return index,Filename,FileOffset,Size,Extension

def extract_file(fp, filename, FileOffset, Size, extract_dir):
	create_dir(extract_dir)
	fp.seek(FileOffset)
	FileContent = fp.read(Size)
	outfile = open(extract_dir + '/'+filename,'wb')
	outfile.write(FileContent)
	outfile.close()
	if filename.find('wtp') > -1 and False:  # Removed due to not needed anymore when using Blender DTT import.
		wtp_fp = open(extract_dir + '/'+filename,"rb")
		content = wtp_fp.read(Size)
		dds_group = content.split(b'DDS ')
		dds_group = dds_group[1:]
		for i in range(len(dds_group)):
			dds_fp = open(extract_dir + '/'+filename.replace('.wtp','_%d.dds'%i), "wb")
			dds_fp.write(b'DDS ')
			dds_fp.write(dds_group[i])
			dds_fp.close()
		wtp_fp.close()
		#os.remove("%s/%s"%(extract_dir,filename))

def get_all_files(path):
	pass

def extract_hashes(fp, extract_dir, FileCount, hashMapOffset, fileNamesOffset):
	create_dir(extract_dir)

	# file_order.metadata
	# Filename Size
	fp.seek(fileNamesOffset)
	fileNameSize = little_endian_to_int(fp.read(4))

	# Filenames
	fileNames = []
	for i in range(FileCount):
		fileNames.append(fp.read(fileNameSize))

	# Extraction
	filename = 'file_order.metadata'
	extract_dir_sub = extract_dir + '\\' + filename
	outfile = open(extract_dir_sub,'wb')

	# Header
	outfile.write(struct.pack('<i', FileCount))
	outfile.write(struct.pack('<i', fileNameSize))

	#Filenames
	for fileName in fileNames:
		outfile.write(fileName)

	outfile.close()

	# hash_data.metadata
	# Header
	fp.seek(hashMapOffset)
	preHashShift = to_int(fp.read(4))
	bucketOffsetsOffset = to_int(fp.read(4))
	hashesOffset = to_int(fp.read(4))
	fileIndicesOffset = to_int(fp.read(4))

	# Bucket Offsets
	fp.seek(hashMapOffset + bucketOffsetsOffset)
	bucketOffsets = []
	while fp.tell() < (hashMapOffset + hashesOffset):
		bucketOffsets.append(to_int(fp.read(2)))

	# Hashes
	fp.seek(hashMapOffset + hashesOffset)
	hashes = []
	for i in range(FileCount):
		hashes.append(fp.read(4))

	# File Indices
	fp.seek(hashMapOffset + fileIndicesOffset)
	fileIndices = []
	for i in range(FileCount):
		fileIndices.append(to_int(fp.read(2)))
 
	# Extraction
	filename = 'hash_data.metadata'
	extract_dir_sub = extract_dir + '\\' + filename
	outfile = open(extract_dir_sub,'wb')

		# Header
	outfile.write(struct.pack('<i', preHashShift))
	outfile.write(struct.pack('<i', bucketOffsetsOffset))
	outfile.write(struct.pack('<i', hashesOffset))
	outfile.write(struct.pack('<i', fileIndicesOffset))

		# Bucket Offsets
	for i in bucketOffsets:
		#print(bucketOffsets)
		outfile.write(struct.pack('<H', i))

		# Hashes
	for i in hashes:
		outfile.write(i)

		# File Indices
	for i in fileIndices:
		#print(i)
		outfile.write(struct.pack('<H', i))

	outfile.close()


def main(filename, extract_dir):
	fp = open(filename,"rb")
	headers = read_header(fp)
	if headers:
		FileCount, FileTableOffset, ExtensionTableOffset,NameTableOffset,SizeTableOffset,hashMapOffset = headers

		for i in range(FileCount):
			extract_dir_sub = ''
			index,Filename,FileOffset,Size,Extension = get_fileinfo(fp, i, FileTableOffset,ExtensionTableOffset, NameTableOffset,SizeTableOffset)
			if extract_dir != '':
				extract_dir_sub = extract_dir
				extract_file(fp, Filename, FileOffset, Size, extract_dir_sub)
        
		extract_hashes(fp, extract_dir, FileCount, hashMapOffset, NameTableOffset)

	return Filename





import sys
import zlib


import struct
from typing import Any, List, Tuple

def swap_int32(int):
    return struct.unpack('<i', struct.pack('>i', int))[0]

# Little Endian

def read_int8(file) -> int:
    entry = file.read(1)
    return struct.unpack('<b', entry)[0]

def read_uint8(file) -> int:
    entry = file.read(1)
    return struct.unpack('B', entry)[0]

def read_uint8_x4(file) -> Tuple[int]:
    entry = file.read(4)
    return struct.unpack('BBBB', entry)

def read_int16(file) -> int:
    entry = file.read(2)
    return struct.unpack('<h', entry)[0]

def read_uint16(file) -> int:
    entry = file.read(2)
    return struct.unpack('<H', entry)[0]

def read_int32(file) -> int:
    entry = file.read(4)
    return struct.unpack('<i', entry)[0]

def read_uint32(file) -> int:
    entry = file.read(4)
    return struct.unpack('<I', entry)[0]

def read_int64(file) -> int:
    entry = file.read(8)
    return struct.unpack('<q', entry)[0]

def read_uint64(file) -> int:
    entry = file.read(8)
    return struct.unpack('<Q', entry)[0]

def read_float16(file) -> float:
    entry = file.read(2)
    return struct.unpack('<e', entry)[0]

def read_float(file) -> float:
    entry = file.read(4)
    return struct.unpack('<f', entry)[0]

class SmartIO:
    int8 = "b"
    uint8 = "B"
    int16 = "h"
    uint16 = "H"
    int32 = "i"
    uint32 = "I"
    int64 = "q"
    uint64 = "Q"
    float16 = "e"
    float = "f"

    format: str
    count: int

    def __init__(self, format: str):
        self.format = format
        self.count = struct.calcsize(format)

    @classmethod
    def makeFormat(cls, *formats: List[str]) -> SmartIO:
        return SmartIO("<" + "".join(formats))
    
    def read(self, file) -> Tuple[Any]:
        return struct.unpack(self.format, file.read(self.count))

    def write(self, file, values: Any):
        file.write(struct.pack(self.format, *values))

def to_uint(bs):
	return int.from_bytes(bs, byteorder='little', signed=False)

def write_char(file, char):
    entry = struct.pack('<s', bytes(char, 'utf-8'))
    file.write(entry)

def write_utf8(file, value, byte_count):
    entry = value.encode("utf-8").ljust(byte_count, b"\0")
    file.write(entry)

def write_utf16(file, value, byte_count):
    entry = value.encode("utf-16-le").ljust(byte_count, b"\0")
    file.write(entry)

def write_Int32(file, int):
    entry = struct.pack('<i', int)
    file.write(entry)


def write_uInt32(file, int):
    entry = struct.pack('<I', int)
    file.write(entry)


def write_Int16(file, int):
    entry = struct.pack('<h', int)
    file.write(entry)


def write_uInt16(file, int):
    entry = struct.pack('<H', int)
    file.write(entry)


def write_float(file, float):
    entry = struct.pack('<f', float)
    file.write(entry)


def write_xyz(file, xyz):
    for val in xyz:
        write_float(file, val)


def write_buffer(file, size):
    for i in range(size):
        write_char(file, '')


def write_byte(file, val):
    entry = struct.pack('B', val)
    file.write(entry)


def write_float16(file, val):
    entry = struct.pack("<e", val)
    file.write(entry)

# String

def to_string(bs, encoding = 'utf8'):
    return bs.split(b'\x00')[0].decode(encoding)

def read_string(file, maxBen = -1) -> str:
    binaryString = b""
    while maxBen == -1 or len(binaryString) > maxBen:
        char = readBe_char(file)
        if char == b'\x00':
            break
        binaryString += char
    return binaryString.decode('utf-8')


def write_string(file, str):
    for char in str:
        write_char(file, char)
    write_buffer(file, 1)

# Big Endian

def readBe_int16(file) -> int:
    entry = file.read(2)
    return struct.unpack('>h', entry)[0]

def readBe_int32(file) -> int:
    entry = file.read(4)
    return struct.unpack('>i', entry)[0]

def readBe_char(file) -> str:
    entry = file.read(1)
    return struct.unpack('>c', entry)[0]

def writeBe_char(file, char):
    entry = struct.pack('>s', bytes(char, 'utf-8'))
    file.write(entry)

def writeBe_int32(file, int):
    entry = struct.pack('>i', int)
    file.write(entry)

def writeBe_int16(file, int):
    entry = struct.pack('>h', int)
    file.write(entry)

def write_padding16(file, num):
    if num % 16 != 0:
        file.write(b"\0" * (16 - (num % 16)))

def padTo16(num):
    if num % 16 != 0:
        num += 16 - (num % 16)
    
    return num


def write_Int32(file, int):
    entry = struct.pack('<i', int)
    file.write(entry)

class HashInfo:
    def __init__(self, in_files, dupe):
        self.in_files = in_files
        self.dupe = dupe
        self.filenames = []
        self.hashes = []
        self.indices = []
        self.bucket_offsets = []
        self.pre_hash_shift = 0
        self.generate_info()

    # We sort, determine names to dupe, then dupe them in the *original* file list
    def get_duped_names(self):
        ordered_files = []

        for file in self.in_files:
            ordered_files.append((file, (zlib.crc32(file.lower().encode('ascii')) & ~0x80000000) >> self.pre_hash_shift)) 
        
        #Sort by search index
        ordered_files.sort(key=lambda x: x[1])

        #If search index increments more than 1, we dupe
        dupes = []

        search_index = ordered_files[0][1]
        for file in ordered_files:
            if file[1] > search_index + 1:
                dupes.append(file[0])
            
            search_index = file[1]

        #rebuild original list with dupes
        duped_names = []
        for name in self.in_files:
            if name in dupes:
                #hah
                duped_names.append(name)
                duped_names.append(name)

            else:
                duped_names.append(name) 

        return duped_names

    def calculate_shift(self):
        for i in range(31):
            if 1 << i >= len(self.in_files):
                return 31 - i
        
        return 0

    #thanks petrarca :)
    def generate_info(self):
        self.pre_hash_shift = self.calculate_shift()

        if self.dupe:
            self.filenames = self.get_duped_names()
        
        else:
            self.filenames = self.in_files

        for i in range(1 << 31 - self.pre_hash_shift):
            self.bucket_offsets.append(-1)

        if self.pre_hash_shift == 0:
            print("Hash shift is 0; does directory have more than 1 << 31 files?")

        names_indices_hashes = []
        for i in range(len(self.filenames)):
            names_indices_hashes.append((self.filenames[i], i, (zlib.crc32(self.filenames[i].lower().encode('ascii')) & ~0x80000000)))
        
        names_indices_hashes.sort(key=lambda x: x[2] >> self.pre_hash_shift)
        
        for entry in names_indices_hashes:
            self.hashes.append(entry[2])
        
        self.hashes.sort(key=lambda x: x >> self.pre_hash_shift)

        for i in range(len(names_indices_hashes)):
            if self.bucket_offsets[names_indices_hashes[i][2] >> self.pre_hash_shift] == -1:
                self.bucket_offsets[names_indices_hashes[i][2] >> self.pre_hash_shift] = i
            self.indices.append(names_indices_hashes[i][1])

    def get_table_size(self):
        self.buckets_size = len(self.bucket_offsets) * 2 #these are only shorts (uint16)
        self.hashes_size = len(self.hashes) * 4 #uint32
        self.indices_size = len(self.indices) * 2 #shorts again (uint16)

        size = 16 + self.buckets_size + self.hashes_size + self.indices_size #16 for pre_hash_shift and 3 table offsets (all uint32)

        return size

class DAT:
    def __init__(self, in_dir, dupe, outdir):
        self.in_dir = in_dir
        self.outdir = outdir
        self.extensions = []
        in_files_tmp = os.listdir(in_dir)
        in_files = []
        for i in in_files_tmp:
            if not i.endswith(".em4v"):
                in_files.append(i)

        if len(in_files) == 0:
            print("Input directory is empty, exiting")
            sys.exit(1)

        self.hash_info = HashInfo(in_files, dupe)
        self.longest_name_length = self.get_longest_name_length()

    def pack(self):
        outfile = self.outdir

        f = open(outfile, "wb+")

        offset_table_size = self.get_offset_table_size()
        extension_table_size = self.get_extension_table_size()
        filename_table_size = self.get_filename_table_size()
        filesize_table_size = self.get_filesize_table_size()
        hashmap_table_size = self.hash_info.get_table_size()

        #Header
        f.write(b"DAT\0")   # Magic (DAT)
        write_Int32(f, len(self.hash_info.filenames)) # Filecount
        write_Int32(f, 32) # Offset table offset (size of DAT header, always 32)
        write_Int32(f, 32 + offset_table_size)   # Extension table offset
        write_Int32(f, 32 + offset_table_size + extension_table_size)   # Filename table offset
        write_Int32(f, 32 + offset_table_size + extension_table_size + filename_table_size) # File sizes table offset
        write_Int32(f, 32 + offset_table_size + extension_table_size + filename_table_size + filesize_table_size) # File sizes table offset
        write_Int32(f, 0) # Pad to 16bit alignment

        total_info_size = 32 + offset_table_size + extension_table_size + filename_table_size + filesize_table_size + hashmap_table_size

        #Padding
        total_info_size = padTo16(total_info_size)

        # Table time

        # File offsets
        for offset in self.get_file_offsets_list(total_info_size):
            write_Int32(f, offset)

        # Extensions
        for extension in self.extensions:
            write_string(f, extension)
        
        # Names
        write_Int32(f, self.longest_name_length)
        for name in self.hash_info.filenames:
            write_string(f, name)
            f.write(b"\0" * (self.longest_name_length - len(name) - 1)) # -1 because write_string adds a null terminator
        
        # Sizes
        for name in self.hash_info.filenames:
            size = os.path.getsize(self.in_dir + "/" + name)
            write_Int32(f, size)
        
        # Hashmap
        write_Int32(f, self.hash_info.pre_hash_shift)
        write_Int32(f, 16) # bucket_offsets offset
        write_Int32(f, 16 + self.hash_info.buckets_size) # hashes offset
        write_Int32(f, 16 + self.hash_info.buckets_size + self.hash_info.hashes_size) # file indices offset
        for bucket in self.hash_info.bucket_offsets:
            write_Int16(f, bucket)
        for hash in self.hash_info.hashes:
            write_Int32(f, hash)
        for index in self.hash_info.indices:
            write_Int16(f, index)

        # Padding
        write_padding16(f, f.tell())

        # Open files, write files
        for name in self.hash_info.filenames:
            current_file = open(self.in_dir + "/" + name, "rb")
            data = current_file.read()
            f.write(data)
            write_padding16(f, f.tell())

        print(f"Wrote {outfile}")

        # Uncomment for sick hashmap debug info
        # for i in range(len(self.hash_info.filenames)):
        #     search = (zlib.crc32(self.hash_info.filenames[i].lower().encode('ascii')) & ~0x80000000) >> self.hash_info.pre_hash_shift
        #     print(f"Expected filename: {self.hash_info.filenames[i]}\t Output filename: {self.hash_info.filenames[self.hash_info.indices[self.hash_info.bucket_offsets[search]]]}")

    def get_extension_table_size(self):
        split_names = []
        size = 0

        # os.path.splitext keeps the ".", and I want it to be clear that we add 1 later because
        # of the null terminator - NOT the ".", so we use rsplit instead
        for filename in self.hash_info.filenames:
            split_names.append(filename.rsplit('.', 1))
        
        # Count these because extensions can be variable length (.z), thanks Raider!
        for split in split_names:
            self.extensions.append(split[1])
            size += len(split[1].split('.')[0]) + 1 # add one for the null terminator we are adding later

        return size

    def get_longest_name_length(self):
        longest = 0
        for name in self.hash_info.filenames:
            if len(name) > longest:
                longest = len(name)

        return longest + 1 #null terminator
    
    def get_offset_table_size(self):
        return len(self.hash_info.filenames * 4)
    
    def get_filesize_table_size(self):
        return len(self.hash_info.filenames * 4)
    
    def get_filename_table_size(self):
        return self.longest_name_length * len(self.hash_info.filenames) + 4 #first 4 bytes are the longest_name_length
    
    def get_file_offsets_list(self, start):
        offset = 0
        file_offsets = []

        for name in self.hash_info.filenames:
            file_offsets.append(start + offset)
            offset += padTo16(os.path.getsize(self.in_dir + "/" + name))
        
        return file_offsets


FILEBROWSER_PATH = os.path.join(os.getenv('WINDIR'), 'explorer.exe')

def explore(path):
    # explorer would choke on forward slashes
    path = os.path.normpath(path)

    if os.path.isdir(path):
        subprocess.run([FILEBROWSER_PATH, path])
    elif os.path.isfile(path):
        subprocess.run([FILEBROWSER_PATH, '/select,', os.path.normpath(path)])


if __name__ == "__main__":

    in_dir = sys.argv[1]
    dupe = False

    if in_dir.endswith(".dtt") or in_dir.endswith(".dat") or in_dir.endswith(".eff"):
        print("VALID")
        unpack_path = f"/tmp/{random.randrange(0, 99000000)}_{os.path.basename(in_dir)}"
        main(f"{in_dir}", unpack_path)
        with open(f"{unpack_path}/PACK.em4v", "w") as info_file:
            info_file.write(f'{in_dir[-3:]}\n{in_dir}')

        os.remove(f"{unpack_path}/file_order.metadata")
        os.remove(f"{unpack_path}/hash_data.metadata")

        explore(unpack_path)


    if in_dir.endswith(".em4v"):
        with open(f"{in_dir}", "r") as info_file:
            emFile = info_file.readlines(0)

        ext_info = emFile[0][:-1]
        dir_info = emFile[1]

        DAT_file = DAT(os.path.dirname(os.path.abspath(in_dir)), dupe, dir_info)
        os.remove(in_dir)
        DAT_file.pack()
        shutil.rmtree(os.path.dirname(os.path.abspath(in_dir)))

