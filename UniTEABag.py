import sys
from datetime import datetime
import hashlib
import numpy as np
import concurrent.futures
import argparse
import io
import glob
import os
import tarfile
from pathlib import Path

TEA_DELTA = 0x9e3779b9

TEA_DATA_SIZE = 0x8
TEA_ROUND = 0x10
TEA_READ_SIZE = 0x40000
UT_TEA_MAGIC = b'TEA\x00'

UT_CODEKEY_CONST1 = 0x6e35ba0c

UT_CODEKEY_CONST2_VERSION1 = 0x65748392
UT_CODEKEY_CONST2_VERSION2 = 0x9a8b7c6e

def h_byte(arg2):
    return arg2 & 0xFF

def generate(arg1, arg2, arg3, UT_CODEKEY_CONST2):
    seed = arg1 & 0xFFFFFFFF 
    result = []
    for cnt in range(arg3):
        temp = (seed + UT_CODEKEY_CONST1) & 0xFFFFFFFF 
        temp = temp ^ (cnt - UT_CODEKEY_CONST2) & 0xFFFFFFFF 
        result.append(h_byte(temp))
    return bytes(result)

def generate2(arg1, arg2, arg3, UT_CODEKEY_CONST2):
    temp = arg1 & 0xFFFFFFFF 
    result = []
    for cnt in range(arg3):
        temp = cnt + (temp ^ UT_CODEKEY_CONST2) & 0xFFFFFFFF
        temp = temp + UT_CODEKEY_CONST1

        result.append(h_byte(temp))
    return bytes(result)

def generate_code_key(seed_bytes):
    code_key = int.from_bytes(seed_bytes, byteorder='little') 
    key1 = generate(code_key, None, 0x10, UT_CODEKEY_CONST2_VERSION1) 
    key2 = generate2(code_key, None, 0x10, UT_CODEKEY_CONST2_VERSION2)
    return key1, key2

def tea_encrypt_np(v, k):
    delta = np.uint32(TEA_DELTA)
    sum_ = np.uint32(0)
    
    v0, v1 = v[:, 0].copy(), v[:, 1].copy()
    
    with np.errstate(over='ignore'):
        for _ in range(16):
            sum_ += delta
            v0 = np.uint32(v0 + ((np.left_shift(v1, 4) + k[0]) ^ (v1 + sum_) ^ (np.right_shift(v1, 5) + k[1])) & 0xFFFFFFFF)
            v1 = np.uint32(v1 + ((np.left_shift(v0, 4) + k[2]) ^ (v0 + sum_) ^ (np.right_shift(v0, 5) + k[3])) & 0xFFFFFFFF)

    return np.column_stack((v0, v1))

def encrypt_chunk_np(chunk, key):
    num_blocks = len(chunk) // 8
    chunk_array = np.frombuffer(chunk, dtype=np.uint32).reshape(num_blocks, 2)
    key_array = np.frombuffer(key, dtype=np.uint32)
    
    encrypted_array = tea_encrypt_np(chunk_array, key_array)
    
    return encrypted_array.tobytes()

def parallel_encrypt_payload_np(payload, key, num_threads=4):
    chunk_size = len(payload) // num_threads
    chunk_size = (chunk_size // 8) * 8
    chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        encrypted_payload = b''.join(list(executor.map(encrypt_chunk_np, chunks, [key]*num_threads)))

    return encrypted_payload


def tea_decrypt_np(v, k):
    delta = np.uint32(TEA_DELTA)
    sum_ = np.uint32((delta * 16) & 0xFFFFFFFF)
    
    v0, v1 = v[:, 0].copy(), v[:, 1].copy()
    
    with np.errstate(over='ignore'):
        for _ in range(16):
            v1 = np.uint32(v1 - ((np.left_shift(v0, 4) + k[2]) ^ (v0 + sum_) ^ (np.right_shift(v0, 5) + k[3])) & 0xFFFFFFFF)
            v0 = np.uint32(v0 - ((np.left_shift(v1, 4) + k[0]) ^ (v1 + sum_) ^ (np.right_shift(v1, 5) + k[1])) & 0xFFFFFFFF)
            sum_ -= delta

    return np.column_stack((v0, v1))

def decrypt_chunk_np(chunk, key):
    chunk_array = np.frombuffer(chunk, dtype=np.uint32).reshape(-1, 2)
    key_array = np.frombuffer(key, dtype=np.uint32)
    decrypted_array = tea_decrypt_np(chunk_array, key_array)
    return decrypted_array.tobytes()

def parallel_decrypt_payload_np(data, key, num_threads):
    chunk_size = len(data) // num_threads
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    
    decrypted_data = b""
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        for decrypted_chunk in executor.map(decrypt_chunk_np, chunks, [key]*num_threads):
            decrypted_data += decrypted_chunk

    return decrypted_data

def extract_tar(tar_file_path, output_folder_path):
    print(f'[i] Extracting {tar_file_path} to {output_folder_path}')
    os.makedirs(output_folder_path, exist_ok=True)
    my_tar = tarfile.open(tar_file_path)
    my_tar.extractall(output_folder_path)
    my_tar.close()
    print('[i] Extraction finished.')

def tar_folder(folder):
    file_io = io.BytesIO()
    with tarfile.open(fileobj=file_io, mode="w") as tar:
        for entry in os.scandir(folder):
            tar.add(entry.path, arcname=entry.name)
    file_io.seek(0)
    return file_io.getvalue()

def getMyType(mytype):
    
    if mytype == 3:
        return "TAR"
    if mytype == 2:
        return "TEA"
    return "RAW"

def parse_upk(fname):
    with open(fname, 'rb') as f:
        data = f.read()

    hdr = data[0:0+4]
    isPackage = data[5]
    time = data[8:8+8]
    size = data[16:16+8]
    utfiletype = data[24]
    seed = data[28:28+4]
    sign1 = data[32:32+8]
    sign2 = data[40:40+8]
    md5 = sign1 + sign2
    pkg_name = data[48:48+64]
    payload = data[112:]
    payload_hdr = payload[0:0+4]
    payload_data = payload[4:]
    
    payload_md5 = hashlib.md5(payload).hexdigest()

    mytype = hdr.decode('utf8')
    timestamp = datetime.fromtimestamp(int.from_bytes(time, byteorder="little"))
    size_num = int.from_bytes(size, byteorder='little')
    package_name = pkg_name.decode('utf8').replace('\x00','')

    print(f'[i] Filename: {fname}')
    print(f'[i] Filetype: {mytype}')
    print(f'[i] isPackage: {isPackage}')
    print(f'[i] Timestamp: {timestamp}')
    print(f'[i] UT-Filetype: {getMyType(utfiletype)}')
    print(f'[i] Timestamp: {data[8:8+8].hex()}')
    print(f'[i] Payload size: {size_num}')
    print(f'[i] Payload size: {data[16:16+8].hex()}')
    print(f'[i] Payload size mod 8: {(size_num - 4)% 8}')
    print(f'[i] Seed: {seed.hex()}')
    print(f'[i] Md5-Signature: {md5.hex()}')
    print(f'[i] Md5-Sign1: {sign1.hex()}')
    print(f'[i] Md5-Sign2: {sign2.hex()}')
    print(f'[i] PackageName: {package_name}')
    
    assert size_num == len(payload)
    print('[i] Payload size OK')
    assert md5.hex() == payload_md5
    print('[i] MD5 verify OK')
    assert payload_hdr == UT_TEA_MAGIC
    print('[i] Found TEA header')    
    seed_bytes = bytes.fromhex(seed.hex())
    key1_bytes, key2_bytes = generate_code_key(seed_bytes)
    print(f'[*] Calculated Tea Key Version1: {key1_bytes.hex()}')
    print(f'[*] Calculated Tea Key Version2: {key2_bytes.hex()}')
    return mytype, timestamp, package_name, size_num, seed, md5, seed_bytes, key1_bytes, key2_bytes, payload_data

def decrypt_upk(fname, output_directory=None):
    print(UT_CODEKEY_CONST1)
    mytype, timestamp, package_name, size_num, seed, md5, seed_bytes, key1_bytes, key2_bytes, payload_data = parse_upk(fname)

    print('[*] Decrypting')
    ofname = Path(fname).stem
    if output_directory is None:
        output_directory = str(Path(fname).parent)
    os.makedirs(output_directory, exist_ok=True)
    outputfile = str(Path(output_directory) / f'{ofname}.tar')

    decrypted = parallel_decrypt_payload_np(payload_data, key2_bytes, num_threads=4)  
    succ = True
    used_key1 = False
    used_key2 = False
    with open(outputfile, 'wb') as out_file:
        out_file.write(decrypted)
    if not tarfile.is_tarfile(outputfile):
        print('[i] Key2 failed, trying key1')
        succ = False
        decrypted = parallel_decrypt_payload_np(payload_data, key1_bytes, num_threads=4)  
        with open(outputfile, 'wb') as out_file:
            out_file.write(decrypted)
        if not tarfile.is_tarfile(outputfile):
            print('[i] key1 failed')
            succ = False
        else:
            succ = True
            used_key1 = True
            print('[#] Decryption successful!')
            print(f'[#] Saved file as {outputfile}')
    else:
        succ = True
        used_key2 = True
        print('[#] Decryption successful!')
        print(f'[#] Saved file as {outputfile}')

    if succ:
        outputinfofile = str(Path(output_directory) / f'{ofname}-info.txt')

        with open(outputinfofile, 'w', encoding='utf-8') as out_file:
            out_file.write(f'Filename: {fname}\n')
            out_file.write(f'Filetype: {mytype}\n')
            out_file.write(f'Timestamp: {timestamp}\n')
            out_file.write(f'PackageName: {package_name}\n')
            if used_key1:
                out_file.write(f'Encver: 1\n')
            if used_key2:
                out_file.write(f'Encver: 2\n')
            out_file.write(f'Payload size: {size_num}\n')
            out_file.write(f'Seed: {seed.hex()}\n')
            out_file.write(f'Md5-Signature: {md5.hex()}\n')
            if used_key1:
                out_file.write(f'Calculated Tea Key Version1: {key1_bytes.hex()}\n')
            if used_key2:
                out_file.write(f'Calculated Tea Key Version2: {key2_bytes.hex()}\n')
    return outputfile, ofname, succ
    
def datetime_string_to_little_endian_bytes(date_str):
    dt_obj = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
    
    timestamp = int(dt_obj.timestamp())
    
    timestamp_bytes = timestamp.to_bytes(length=(timestamp.bit_length() + 7) // 8, byteorder='little')
    
    return timestamp_bytes

def encrypt_upk(seed, package_name, timestamp, enc_version, outfile=None, folder=None, tarfile=None):
    if outfile is None:
        outputfile = f'{package_name}.upk'
    else:
        outputfile = outfile
    if folder is None and tarfile is None:
        print('Need to set atleast folder or tarfile to encrypt')
        return
    print(f'Building new upk {outputfile}')
    print(f'Seed: {seed}')
    print(f'Packagename: {package_name}')
    print(f'timestamp: {timestamp}')
    if folder:
        payload = tar_folder(folder)
    if tarfile:
        with open(tarfile, 'rb') as f:
            payload = f.read()
    seed_bytes = bytes.fromhex(seed)
    key1, key2 = generate_code_key(seed_bytes)
    if enc_version == '1':
        key = key1
    elif enc_version == '2':
        key = key2
    else:
        print('unknown key version, using version1')
        key = key1
    enc_payload = parallel_encrypt_payload_np(payload, key)
    
    payload = bytearray(4+len(enc_payload))
    payload[0:0+4] = UT_TEA_MAGIC
    payload[4:] = enc_payload
    payload_size = len(payload)

    payload_md5 = hashlib.md5(payload).digest()
    sign1 = payload_md5[:8]
    sign2 = payload_md5[8:]

    data = bytearray(116+payload_size)
    data[0:0+4] = 'UTPK'.encode('utf-8') #hdr
    data[5] = 0x01
    data[8:8+8] = datetime_string_to_little_endian_bytes(timestamp)
    data[16:16+8] = payload_size.to_bytes(8, byteorder='little')
    data[24] = 0x03 #TAR for now
    data[28:28+4] = bytes.fromhex(seed)
    data[32:32+8] = sign1
    data[40:40+8] = sign2
    
    data[48:48+64] = package_name.encode('utf-8') #pkg_name
    data[112:] = payload

    with open(outputfile, 'wb') as out:
        out.write(data)
    print(f'Saved new upk: {outputfile}')
    

def parse_info(fname):
    package_name= None
    seed = None
    timestamp = None
    encver = None
    with open(fname, 'r') as i:
        lines = i.readlines()
        for line in lines:
            split = line.split(':', maxsplit=1)
            if split[0] == 'Timestamp':
                timestamp = split[1].strip()
            if split[0] == 'PackageName':
                package_name = split[1].strip()
            if split[0] == 'Seed':
                seed = split[1].strip()
            if split[0] == 'Encver':
                encver = split[1].strip()
    return seed, package_name, timestamp, encver

def find_upk_files(folder):
    files = []
    for root, _, filenames in os.walk(folder):
        for filename in filenames:
            if filename.endswith('.upk'):
                files.append(os.path.join(root, filename))
    return files

def dec_input_file(fname, extract, extract_to_parent=True, delete_upk=False):
    succ = False
    base_dir = str(Path(fname).parent)
    tarname, ofname, succ = decrypt_upk(fname, output_directory=base_dir)
    if succ and extract:
        try:
            if extract_to_parent:
                extract_tar(tarname, base_dir)
            else:
                extract_dir = str(Path(base_dir) / ofname)
                extract_tar(tarname, extract_dir)
        except Exception:
            try:
                os.remove(tarname)
            except Exception:
                pass
            try:
                os.remove(str(Path(base_dir) / f'{ofname}-info.txt'))
            except Exception:
                pass
    
    if succ and delete_upk:
        try:
            os.remove(fname)
            print(f'[i] Deleted UPK file: {fname}')
        except Exception as e:
            print(f'[!] Failed to delete UPK file {fname}: {e}')

def fast_scandir(dirname):
    subfolders= [f.path for f in os.scandir(dirname) if f.is_dir()]
    for dirname in list(subfolders):
        subfolders.extend(fast_scandir(dirname))
    return subfolders

def main():
    print('+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+')
    print('|             Bin4rys Unitree UPK Tool v1.8                   |')
    print('|                shout out to:                                |')
    print('| h0stile, todb, AHA, Darknavy, theroboverse and all friends  |')
    print('+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+')
    parser = argparse.ArgumentParser(
                    prog='upk_tool')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Decrypt mode')

    parser.add_argument('-i','--inputfile', type=str,
            help="the upk file to be decrypted")

    parser.add_argument('-a','--allfiles', action='store_true',
            help="scan for .upk files; with -i scans inside extracted folder, else current dir")

    parser.add_argument('-e', '--encrypt', action='store_true', help='Encrypt mode')

    parser.add_argument('-r', '--readfile', action='store_true', help='Just read upk file and print info')

    subparser = parser.add_mutually_exclusive_group()

    subparser.add_argument('-f' , '--folder', type=str,
            help="the folder to be encrypted as upk")
    subparser.add_argument('-tf' , '--tarfile', type=str,
            help="the tarfile to be encrypted as upk")

    subparser = parser.add_mutually_exclusive_group()    
    subparser.add_argument('-info','--infofile', type=str,
            help="use infofile")
    subparser.add_argument('-c','--customdata', action='store_true',
            help="provide own data")

    parser.add_argument('-s','--seed', type=str,
            help="the seed to use")
    parser.add_argument('-p','--packagename', type=str,
            help="the packagename to use")
    parser.add_argument('-ev','--encver', type=str,
            help="the encryptionversion to use, can be 1 or 2")
    parser.add_argument('-t','--timestamp', type=str,
            help="the timestamp to use, if not set current system time will be used")
    parser.add_argument('-o','--outputfile', type=str,
            help="the outputfile for encryption")
    subparser.add_argument('-x','--extract', action='store_true',
            help="extract tar after decryption")
    parser.add_argument('--extract-to-subfolder', action='store_true',
            help="extract tar to a subfolder named after the file (default: extract to parent directory like normal tar)")
    parser.add_argument('--keep-upk', action='store_true',
            help="keep UPK files after processing (default: delete UPK files after deep extraction)")
    args = parser.parse_args()

    if args.readfile:
        parse_upk(args.inputfile)

    if args.decrypt:
        if args.inputfile:
            dec_input_file(args.inputfile, args.extract, not args.extract_to_subfolder, False)
            print_ascii_art()
        if args.allfiles:
            delete_upk_files = not args.keep_upk
            main_upk_path = args.inputfile
            if args.inputfile:
                base_dir = str(Path(args.inputfile).parent)
                if args.extract_to_subfolder:
                    extracted_folder = str(Path(base_dir) / Path(args.inputfile).stem)
                    if os.path.exists(extracted_folder):
                        for file in find_upk_files(extracted_folder):
                            # Don't delete the main UPK file, only nested ones
                            is_main_file = os.path.abspath(file) == os.path.abspath(main_upk_path)
                            dec_input_file(file, args.extract, not args.extract_to_subfolder, delete_upk_files and not is_main_file)
                    else:
                        print(f"[!] Extracted folder {extracted_folder} not found. Please extract first with -x")
                else:
                    currfolder = os.getcwd()
                    upk_files = find_upk_files(currfolder)

                    main_file_dir = os.path.dirname(os.path.abspath(main_upk_path))
                    filtered_files = []
                    for file in upk_files:
                        file_dir = os.path.dirname(os.path.abspath(file))
                        if file_dir != main_file_dir and file_dir != currfolder:
                            if 'module' in file or 'file' in file:
                                filtered_files.append(file)
                    
                    for file in filtered_files:
                        dec_input_file(file, args.extract, not args.extract_to_subfolder, delete_upk_files)
            else:
                currfolder = os.getcwd()
                for file in find_upk_files(currfolder):
                    dec_input_file(file, args.extract, not args.extract_to_subfolder, delete_upk_files)
            print_ascii_art()

    if args.encrypt:
        if not args.folder and not args.tarfile:
            print('You have to provide an folder or tarfile to encrypt')
            sys.exit(0)
        if not args.infofile and not args.customdata:
            print('You have to use either infofile or customdata')
            sys.exit(0)
        folder = None
        tarfile = None
        if args.folder:
            folder = args.folder
        if args.tarfile:
            tarfile = args.tarfile
        if args.infofile:
            seed, package_name, timestamp, encver = parse_info(args.infofile)
        if args.customdata:
            if not args.seed or not args.packagename and not args.encver:
                print('You have to provide seed, packagename and encver')
                sys.exit(0)
            seed = args.seed
            package_name = args.packagename
            if args.timestamp:
                timestamp = args.timestamp
            else:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        outputfile = None
        if args.outputfile:
            outputfile = args.outputfile

        if seed is not None and package_name is not None and timestamp is not None:
            encrypt_upk(seed, package_name, timestamp, encver, outputfile, folder, tarfile)
            print_ascii_art()
        else:
            print('Oops, something fucked up....')

def print_ascii_art():
    art = r"""

            .------.____
         .-'       \ ___)
      .-'         \\\
   .-'        ___  \\)
.-'          /  (\  |)
         __  \  ( | |
        /  \  \__'| |
       /    \____).-'
     .'       /   |
    /     .  /    |
  .'     / \/     |
 /      /   \     |
       /    /    _|_
       \   /    /\ /\
        \ /    /__v__\
         '    |       |
              |     .#|
              |#.  .##|
              |#######|
              |#######|
    """
    print('[!] Teabagging done ....')
    print(art) 

if __name__ == '__main__':
    main()