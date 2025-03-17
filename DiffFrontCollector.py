import io
import os
import sys
import time
import struct
import hashlib
import win32api
import argparse
import pathlib
import platform
import pefile
from prettytable import PrettyTable
from win32api import GetFileVersionInfo, LOWORD, HIWORD
from pathlib import *
from datetime import *
import winreg

__author__ = 'bopin'
__version__ = '0.3'

#
#   gloabl profile for debugging
#
g_file = None
g_efile = open("error.log",'w+')
g_msdl = 'https://msdl.microsoft.com/download/symbols'
g_count = 0
table = PrettyTable(['sha256','file version','file size','msdllink','pdblink','stamp','short time','fullpath'])
collect_targets = []
g_ext = ['.sys','.exe','.dll']
g_output = []

class EventLogable:
    def report_event(self,module,type,str,debug):
        if debug:
            print(str)
DEBUG = True
g_loglevel = 0
g_log = EventLogable()

class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class Authable:
    def authenticate(self):
        if not True:
            raise ValueError("")

class Util:
    @staticmethod
    def file_name_walk(file_dir):
        for root, dirs, files in os.walk(file_dir):
            for file in files:
                if(root ==  r"c:\windows\system32" or root ==  r"c:\windows\system32\drivers" or r'C:\ProgramData\Microsoft\Windows Defender\Platform' in root):
                    if(file.endswith('.sys') or file.endswith('.exe') or file.endswith('.dll')):
                        yield root + "\\" + file

    @staticmethod
    def get_os_info():
        return platform.platform()

    @staticmethod
    def calc_file_sha256(file):
        hash = hashlib.sha256()
        with open(file,'rb') as f:
            for byte_block in iter(lambda : f.read(4096),b""):
                hash.update(byte_block)
            return hash.hexdigest()
    
    @staticmethod
    def LOWORD(dword):
        return dword & 0x0000ffff
    
    @staticmethod
    def HIWORD(dword): 
        return dword >> 16
    
    @staticmethod
    def get_product_version(path):

        pe = pefile.PE(path)
        #print PE.dump_info()

        ms = pe.VS_FIXEDFILEINFO.ProductVersionMS
        ls = pe.VS_FIXEDFILEINFO.ProductVersionLS
        return (Util.HIWORD (ms), Util.LOWORD (ms), Util.HIWORD (ls), Util.LOWORD (ls))

    #
    #   https://stackoverflow.com/questions/580924/how-to-access-a-files-properties-on-windows
    #
    def get_version_number(filename):
        try:
            info = GetFileVersionInfo(filename, "\\")
            ms = info['FileVersionMS']
            ls = info['FileVersionLS']
            return f'{HIWORD(ms)}.{LOWORD(ms)}.{HIWORD (ls)}.{LOWORD (ls)}'
        except:
            return f'0.0.0.0'
        
    #
    #  https://github.com/m417z/winbindex/blob/main/data/symbol_server_link_enumerate.py
    #
    def make_symbol_server_url(file_name, timestamp, size,short = False):
        if short:
            return f'{timestamp:08X}{size:x}'
        return f'{file_name}/{timestamp:08X}{size:x}/{file_name}'

    def make_symbol_server_pdb(file_name, signature,short = False):
        if short:
            return f'{signature}'
        return f'{file_name}/{signature}/{file_name}'

class BinaryWriteable:
    def pack_char(self,value):
        return bytearray(struct.pack("c", value)) 
    def pack_short(self,value):
        return bytearray(struct.pack("h", value)) 
    def pack_ushort(self,value):
        return bytearray(struct.pack("H", value))
    def pack_int(self,value):
        return bytearray(struct.pack("i", value)) 
    def pack_uint(self,value):
        return bytearray(struct.pack("I", value))
    def pack_longlong(self,value):
        return bytearray(struct.pack("q", value)) 
    def pack_ulonglong(self,value):
        return bytearray(struct.pack("Q", value))

    def pack_float(self,value):
        return bytearray(struct.pack("f", value)) 

    def pack_double(self,value):
        return bytearray(struct.pack("d", value)) 

    def unpack_char(self,value):
        return struct.unpack("c", value)
    def unpack_short(self,value):
        return struct.unpack("h", value)
    def unpack_ushort(self,value):
        return struct.unpack("H", value)
    def unpack_int(self,value):
        return struct.unpack("i", value)
    def unpack_uint(self,value):
        return struct.unpack("I", value)
    def unpack_longlong(self,value):
        return struct.unpack("q", value)
    def unpack_ulonglong(self,value):
        return struct.unpack("Q", value)

    def unpack_float(self,value):
        return struct.unpack("f", value)

    def unpack_double(self,value):
        return struct.unpack("d", value)

class FormatRegTypeable:
    _symbols = {
        0 : 'NONE',
        1 : 'REG_SZ',
        2 : 'REG_EXPAND_SZ',
        3 : 'REG_BINARY',
        4 : 'REG_DWORD',
        5 : 'REG_DWORD_BIG_ENDIAN',
        6 : 'REG_LINK',
        7 : 'REG_MULTI_SZ',
        8 : 'REG_RESOURCE_LIST',
        9 : 'REG_FULL_RESOURCE_DESCRIPTOR',
        10 : 'REG_RESOURCE_REQUIREMENTS_LIST',
        11 : 'REG_QWORD',
    }
    def get_symbols(self,type : int):
        return FormatRegTypeable._symbols[type]

class RegOperationable(FormatRegTypeable):
    def init(self,key = winreg.HKEY_CURRENT_USER):
        return winreg.ConnectRegistry(None,key)
    def uninit(self,key):
        self.close_key(key)
    def close_key(self,key):
        winreg.CloseKey(key)
    def create(self,key,sub_key):
        return winreg.CreateKey(key,sub_key)
    def delete(self,key,sub_key):
        return winreg.DeleteKey(key,sub_key)
    def open(self,key,sub_key):
        return winreg.OpenKey(key,sub_key)
    def query_default_value(self,key):
        try:
            return self.query_value(key,'')[1]
        except:
            return None
    
    def query_value(self,key,valuename):
        try:
            return list(filter(lambda x: x[0] == valuename,self.enum_values(key)))[0]
        except:
            return None
    
    def query_value_type(self,key,valuename,issymbol = False):
        if issymbol:
            return self.get_symbols(self.query_value(key,valuename)[2])
        return self.query_value(key,valuename)[2]
    
    def enum_values(self,key):
        result = []
        try:
            i = 0
            while True:
                try:
                    value_name = winreg.EnumValue(key,i)
                    result.append((value_name[0],value_name[1],self.get_symbols(value_name[2])))
                    i += 1
                except:
                    #print(Color.RED + e.strerror + Color.END)
                    break
        except:
            #print(Color.RED + e.strerror + Color.END)
            pass
        return result
    
    def write_default_value(self,key,value):
        winreg.SetValue(key,"",winreg.REG_SZ,value)
    
    def write_value(self,key,valuename,type,value):
        winreg.SetValueEx(key,valuename,0,type,value)

    def enum_keys(self,key):
        try:
            i = 0
            while True:
                try:
                    yield winreg.EnumKey(key,i)
                    i += 1
                except:
                    #print(Color.RED + e.strerror + Color.END)
                    break
        except:
            #print(Color.RED + e.strerror + Color.END)
            pass

class PefileLink():
    def __init__(self,file) -> None:
        self.pe = pefile.PE(file,fast_load=True)
        self.stamp = self.pe.FILE_HEADER.TimeDateStamp
        self.sizeimage = self.pe.OPTIONAL_HEADER.SizeOfImage
        debugdir = self.pe.parse_debug_directory(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress,self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size)
        self.pdblink = ""
        try:
            self.pdblink = debugdir[0].entry.Signature_String
        except:
            pass

class MetadataHeader(EventLogable):
    def __init__(self) -> None:
        #
        #  0 0 0 0 0 0 0 1          # short sha256 32bytes lower to 16bytes
        #  0 0 0 0 0 0 1 0
        #  0 0 0 0 0 1 0 0
        #  0 0 0 0 1 0 0 0
        #  0 0 0 1 0 0 0 0
        #  0 0 1 0 0 0 0 0
        #  0 1 0 0 0 0 0 0
        #  1 0 0 0 0 0 0 0
        #  
        self.flag = 0x0
        self.os_friendly_version = platform.platform()
        #
        #   x86
        #   x64
        #   arm
        #   arm64
        #   none
        #
        if(platform.architecture()[0] == '64bit'):
            self.arch = 1
        else:
            self.arch = 0
        #
        #   windows_pc              0 
        #   windows_server          1  
        #   windows_insider_preview 2
        #   windows_none
        #
        self.type = 0

        self.collector_dir = [r"c:\windows\system32",r"c:\windows\system32\drivers",r'C:\ProgramData\Microsoft\Windows Defender\Platform']

    def write(self,file):
        t = f'{self.flag}\t{self.os_friendly_version}\t{self.arch}\t{self.type}\n'
        self.report_event(0,1,t,DEBUG)
        file.write(t)

class Metadata():
    def __init__(self,file) -> None:
        self.sha256 = Util.calc_file_sha256(file)
        self.file_version = Util.get_version_number(file)
        self.filesize = os.path.getsize(file)
        pel = PefileLink(file)
        self.msdllink = Util.make_symbol_server_url(PureWindowsPath(file).name,pel.stamp,pel.sizeimage)
        self.pdblink = Util.make_symbol_server_pdb(Path(PureWindowsPath(file).name).stem + ".pdb",pel.pdblink)
        self.stamp = os.path.getmtime(file)
        self.short_time = 0
        self.fullpath = str(file)

class Runner(EventLogable,RegOperationable):
    def execute_entry(self):
        global g_count
        header = MetadataHeader()
        header.write(g_file)
        for target in collect_targets:
            for i in Util.file_name_walk(target):
                try:
                    mt = Metadata(i)
                    item = []
                    item.append(mt.sha256)
                    item.append(mt.file_version)
                    item.append(mt.filesize)
                    item.append(mt.msdllink)
                    item.append(mt.pdblink)
                    item.append(mt.stamp)
                    item.append(mt.short_time)
                    item.append(mt.fullpath)
                    g_count += 1
                    if DEBUG:
                        table.add_row(item)
                    g_file.write(f'{mt.sha256}\t{mt.file_version}\t{mt.filesize}\t{mt.msdllink}\t{mt.pdblink}\t{mt.stamp}\t{mt.short_time}\t{mt.fullpath}\n')
                except Exception as e:
                    g_efile.write(f"{datetime.now()}  {i} {str(e)}\n")

        if DEBUG:
            print(table)
            print(f'count: {g_count}')

        g_file.close()
        g_efile.close()

    def uninstall(self):
        key = self.init()
        rootkey = self.open(key,'msdlcollector')
        if rootkey is not None:
            self.close_key(rootkey)
            self.delete(key,'msdlcollector')
            print('uninstall finished')

    def install(self):
        """ First collector msdl links, store them into registry and next diff the registry hkey/value.
        The expect output result format is list(tuple) | pass them into patch diff bot purpose for decompilation
        """
        key = self.init()
        try:
            rootkey = self.open(key,'msdlcollector')

            if rootkey is not None:
                print('it has installed')
                self.close_key(rootkey)
                return 0
        except:
            pass
        
        # 1. install write metadata
        rootkey = self.create(key,'msdlcollector')
        self.write_default_value(rootkey,str(datetime.now()))
        meta = MetadataHeader()
        self.write_value(rootkey,'flag',winreg.REG_DWORD,meta.flag)
        self.write_value(rootkey,'version',winreg.REG_SZ,meta.os_friendly_version)
        self.write_value(rootkey,'arch',winreg.REG_DWORD,meta.arch)
        self.write_value(rootkey,'type',winreg.REG_DWORD,meta.type)
        self.write_value(rootkey,'source',winreg.REG_MULTI_SZ,meta.collector_dir)

        for target in collect_targets:
            for i in Util.file_name_walk(target):
                try:
                    mt = Metadata(i)
                    subkey = self.create(rootkey,f'{mt.fullpath}')
                    self.write_value(subkey,'sha256',winreg.REG_SZ,mt.sha256)
                    self.write_value(subkey,'fileversion',winreg.REG_SZ,mt.file_version)
                    self.write_value(subkey,'filesize',winreg.REG_DWORD,mt.filesize)
                    self.write_value(subkey,'msdllink',winreg.REG_SZ,mt.msdllink)
                    self.write_value(subkey,'pdblink',winreg.REG_SZ,mt.pdblink)
                    self.write_value(subkey,'filestamp',winreg.REG_SZ,str(mt.stamp))
                    self.write_value(subkey,'shorttime',winreg.REG_DWORD,mt.short_time)
                    self.write_value(subkey,'fullpath',winreg.REG_SZ,mt.fullpath)
                    self.close_key(subkey)
                except Exception as e:
                    self.report_event(f"{datetime.now()}  {i} {str(e)}")
        self.close_key(rootkey)
        self.uninit(key)

    def diff(self,args):
        key = self.init()
        try:
            rootkey = self.open(key,'msdlcollector')
            if rootkey is None:
                print('have not installed')
                return 0
        except:
            pass
        rootkey = self.create(key,'msdlcollector')
        self.write_value(rootkey,'lastdatetime',winreg.REG_SZ,str(datetime.now()))

        for target in collect_targets:
            for i in Util.file_name_walk(target):
                try:
                    mt = Metadata(i)
                    subkey = self.create(rootkey,f'{mt.fullpath}')
                    if self.query_value(subkey,'sha256')[1] != mt.sha256:
                        g_output.append((mt.fullpath,self.query_value(subkey,'msdllink')[1],mt.msdllink))
                        if args.disableupdate:
                            self.close_key(subkey)
                            continue
                        #
                        # update will carry out without disableupdate args
                        #
                        self.write_value(subkey,'sha256',winreg.REG_SZ,mt.sha256)
                        self.write_value(subkey,'fileversion',winreg.REG_SZ,mt.file_version)
                        self.write_value(subkey,'filesize',winreg.REG_DWORD,mt.filesize)
                        self.write_value(subkey,'msdllink',winreg.REG_SZ,mt.msdllink)
                        self.write_value(subkey,'pdblink',winreg.REG_SZ,mt.pdblink)
                        self.write_value(subkey,'filestamp',winreg.REG_SZ,str(mt.stamp))
                        self.write_value(subkey,'shorttime',winreg.REG_DWORD,mt.short_time)
                        self.write_value(subkey,'fullpath',winreg.REG_SZ,mt.fullpath)
                    self.close_key(subkey)
                except Exception as e:
                    print(f"{datetime.now()}  {i} {str(e)}")

        time = datetime.now()
        storekey = None
        try:
            name = f'store\\{str(time.year)}-{str(time.month)}'
            self.report_event(0,1,name,DEBUG)
            storekey = self.create(rootkey,name)
        except Exception as e:
            self.report_event(0,1,str(e),DEBUG)
        
        for file,old,new in g_output:
            #
            # store diff msdl links
            #
            print(f'{file}  {g_msdl}/{old}  {g_msdl}/{new}')
            if args.store and storekey:
                #
                # create subkey to store this diff values
                #
                self.write_value(storekey,file,winreg.REG_MULTI_SZ,[old,new])

        self.close_key(storekey)
        self.close_key(rootkey)
        self.uninit(key)


def main():
    g_log.report_event(0,1,"runner.execute_entry starting...",DEBUG)
    Runner().execute_entry()
    g_log.report_event(0,1,"runner.execute_entry finished...",DEBUG)

def get_args():
    parser = argparse.ArgumentParser(prog='start info',description= 'diff msdl collector',epilog='end information')
    parser.add_argument('-d','--dirs',dest='target_dirs', nargs='+',default=[])
    parser.add_argument('-n','--num',dest='num',type = int, default= 3, choices=[0,1,2,3], help=r'0 system32 | 1 system32\drivers | 2 defender')
    parser.add_argument('-i','--install',action='store_true',help='first collect msdl link information and push them into registry HKCU\\msdlcollector')
    parser.add_argument('-u','--uninstall',action='store_true',help='remove the specified registry')
    parser.add_argument('-p','--peek',action='store_true',help='default file name (windows latest version)')
    parser.add_argument('--diff',action='store_true',help='collect msdl link in real time and diff with registry which output a pair of old-new links (decompilation diff pending item)')
    parser.add_argument('--disableupdate',action='store_true',help='dont override registry value when changes')
    parser.add_argument('-s','--store',action='store_true',help='auto store to register msdlcollector\\store\\year-month')
    parser.add_argument('-v','--verbose',action='store_true',help='output the verbose information')
    return parser

if __name__ == '__main__':
    try:
        args = get_args().parse_args()

        if args.uninstall:
            Runner().uninstall()
            sys.exit(0)

        if args.peek:
            #
            # compatible with  python3.8, 3.9  Windows 7 and 8.1
            #
            tmp = Util.get_version_number(r'c:\windows\system32\ntoskrnl.exe')
            print(f"{platform.platform()}-{tmp}-diff.log")
            sys.exit(0)

        if len(args.target_dirs) == 0:
            flag = args.num
            if flag & 2:
                collect_targets.append(r'C:\ProgramData\Microsoft\Windows Defender\Platform')
            if flag & 1:
                collect_targets.append(r'c:\windows\system32\drivers')
            collect_targets.append(r'c:\windows\system32')

        if args.verbose:
            DEBUG = True
        else:
            DEBUG = False
        for item in args.target_dirs:
            collect_targets.append(item)
        
        if args.diff:
            Runner().diff(args)
            sys.exit(0)

        if args.install:
            Runner().install()
            sys.exit(0)
        #
        # compatible with  python3.8, 3.9  Windows 7 and 8.1
        #
        tmp = Util.get_version_number(r'c:\windows\system32\ntoskrnl.exe')
        g_file = open(f"{platform.platform()}-{tmp}-diff.log",'w+')
        main()
    except Exception as e:
        print(Color.RED + str(e) + Color.END)