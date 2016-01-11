from ctypes import *
from ctypes.util import find_library
import os, sys, struct


VM_PROT_NONE    = 0x00
VM_PROT_READ    = 0x01
VM_PROT_WRITE   = 0x02
VM_PROT_EXECUTE = 0x04

class proc_regioninfo(Structure):
    pass

    _fields_ = [("protection", c_uint32),
                ("max_protection", c_uint32),
                ("inheritance", c_uint32),
                ("flags", c_uint32),
                ("offset", c_uint64),
                ("behavior", c_uint32),
                ("user_wired_count", c_uint32),
                ("user_tag", c_uint32),
                ("pages_resident", c_uint32),
                ("pages_shared_now_private", c_uint32),
                ("pages_swapped_out", c_uint32),
                ("pages_dirtied", c_uint32),
                ("ref_count", c_uint32),
                ("shadow_depth", c_uint32),
                ("share_mode", c_uint32),
                ("private_pages_resident", c_uint32),
                ("shared_pages_resident", c_uint32),
                ("obj_id", c_uint32),
                ("depth", c_uint32),
                ("address", c_uint64),
                ("size", c_uint64)]



class vinfo_stat(Structure):
    pass

    _fields_ = [("dev", c_uint32),
                ("mode", c_uint16),
                ("nlink", c_uint16),
                ("ino", c_uint64),
                ("uid", c_uint32), # uid_t # __darwin_uid_t
                ("gid", c_uint32), #gid_t # __darwin_gid_t
                ("atime", c_int64),
                ("atimensec", c_int64),
                ("mtime", c_int64),
                ("mtimensec", c_int64),
                ("ctime", c_int64),
                ("ctimensec", c_int64),
                ("birthtime", c_int64),
                ("birthtimensec", c_int64),
                ("size", c_int64), # off_t # __darwin_off_t
                ("blocks", c_int64),
                ("blksize", c_int32),
                ("flags", c_uint32),
                ("gen", c_uint32),
                ("rdev", c_uint32),
                ("qspaare", c_int64*2)]


class fsid_t(Structure):
    pass

    _fields_ = [("fsid",c_int32 * 2)]

class vnode_info(Structure):
    pass

    _fields_ = [("stat", vinfo_stat),
                ("type", c_int),
                ("pad", c_int),
                ("fsid", fsid_t)]

MAXPATHLEN = 1024

class vnode_info_path(Structure):
    pass
                
    _fields_ = [("vi", vnode_info),
                ("path", c_char*MAXPATHLEN)]


class proc_regionwithpathinfo(Structure):
    pass
                
    _fields_ = [("prinfo", proc_regioninfo),
                ("vip", vnode_info_path)]


class vmem_info:
    def __init__(self, ri):
        paths = ["/Library/","/usr/","/System/"]

        self.readable   = (ri.prinfo.protection & VM_PROT_READ) != 0
        self.writable   = (ri.prinfo.protection & VM_PROT_WRITE) != 0
        self.executable = (ri.prinfo.protection & VM_PROT_EXECUTE) != 0
        self.address    = ri.prinfo.address
        self.size       = ri.prinfo.size
        self.endaddress = self.address + self.size
        self.sysmodule  = any([v for v in paths if v in ri.vip.path])
        self.path       = ri.vip.path
        self.nswapped   = ri.prinfo.pages_swapped_out
        self.rwx        = "".join(["r" if self.readable else "-", \
                          "w" if self.writable else "-", \
                          "x" if self.executable else "-"])
        
PROC_PIDREGIONPATHINFO = 8
KERN_SUCCESS = 0

class VirtualMemory(object):
	def __init__(self, pid):
            if sys.platform != 'darwin':
		raise EnvironmentError("Platform not supported.")
	    elif os.getuid() != 0:
		raise EnvironmentError("Not running as root.")
		
	    self.pid = pid
	    self.libSystem = CDLL(find_library("System"))
	    self.seek_address = 0
		
	    t = c_uint()
	    if self.libSystem.task_for_pid(self.libSystem.mach_task_self(), pid, byref(t)) > 0:
		raise ValueError("task_for_pid() failed - invalid PID?")
	    else:
		self.task = t.value

        def task_suspend(self):
            return self.libSystem.task_suspend(self.task) == KERN_SUCCESS

        def task_resume(self):
            return self.libSystem.task_resume(self.task) == KERN_SUCCESS
	
	def _read(self, address, buf):
	    count = c_uint(sizeof(type(buf)))
	    result = self.libSystem.vm_read_overwrite(self.task, address, count, byref(buf), byref(count))

	    if result > 0:
                a = self.get_vmem_info(address)
                #print hex(a.address),hex(a.address+a.size)
		return None
	    else:
		return buf


	def read(self, size):
	    result = self._read(self.seek_address, create_string_buffer(size))
	    if result != None:
                self.seek_address += size
            return result
	
	def read_string(self, address):
	    s = ""
	    i = 0
	    bufsize = 32
	    while len(s) < 4096: # max 4kb
		tmp = self._read(address + i, create_string_buffer(bufsize))
		nul = tmp.raw.find('\x00')
		if nul > -1:
		    s += tmp.value[:nul]
		    return s # if nul char encountered
		else:
		    s += tmp.value
		    i += bufsize
	    return s # if reached size limit
		
	def read_int(self, address):
	    v = self._read(address, c_int())
            if v is not None:
		return v.value
            else:
		return None

	def read_float(self, address):
	 	v = self._read(address, c_float())
		if v is not None:
                    return v.value
		else:
                    return None
			
        def dump(self, address, size, path):
            f = open(path, "wb")
            self.seek(address)
            blocksize = 1024 * 1024
            nwritten = 0
            result = True
            blocksize = min(size, blocksize)
            while nwritten < size:
                data = self.read(blocksize)
                if data != None:
                    f.write(data.raw)
                    nwritten += blocksize
                    if nwritten + blocksize > size:
                        blocksize = size - nwritten
                else:
                    print "could not read data at %08X" % self.tell()
                    result = False
                    break
            f.close()
            return result
                
		
	def seek(self, address):
	    self.seek_address = address
		
	def tell(self):
            return self.seek_address
		
	def write_var(self, address, data):
	    if isinstance(data, str) and len(data) == 1: # char
		buf = c_char(data)
	    elif isinstance(data, str): # string
		buf = create_string_buffer(data)
	    elif isinstance(data, int): # int
		buf = c_int(data)
	    elif isinstance(data, float): # float
		buf = c_float(data)		
			
	    if self.libSystem.vm_write(self.task, address, byref(buf), sizeof(type(buf))) > 0:
		raise ValueError("Error writing to given memory address.")
	    else:
		return True
			
	def write(self, text):
            self.write_var(self.seek_address, str(text))
            self.seek_address += len(str(text))

        def find_in_chunk(self, s, chunk):
            return chunk.find(s)

        def find_in_region(self, s, address, size, offs=0):
            chunksize = 1024 * 1024
            size_chunk = min(size - offs, chunksize)
            num_read = offs
            lastslice = ""
            while num_read != size:
                chunk = self[address+num_read:address+num_read+size_chunk]
                if chunk != None:
                    chunk = chunk.raw
                    p = self.find_in_chunk(s, lastslice+chunk)
                    if p != -1:
                        return address + num_read + p - len(lastslice)
                    lastslice = chunk[size_chunk-len(s):]
                    #num_read += size_chunk
                    #size_chunk = min((size - num_read), chunksize)
                #else:
                    #num_read += size_chunk
                    #size_chunk = min((size - num_read), chunksize)
                num_read += size_chunk
                size_chunk = min((size - num_read), chunksize)
                
            return -1

        def find(self, s, start_address=0):
            offs = 0
            mem = self.get_vmem_info(start_address)
            if mem != None:
                if start_address:
                    if start_address > mem.address:
                        offs = start_address - mem.address
            while mem != None:
                if mem.readable:
                    addr = self.find_in_region(s, mem.address, mem.size, offs)
                    if addr != -1:
                        return addr
                mem = self.get_vmem_info(mem.address + mem.size)
                offs = 0
            return -1
            
	def __getitem__(self, key):
	    if isinstance(key, slice):
                if key.start is None:
		    return self._read(0x0, create_string_buffer(key.stop))
		elif key.stop is None:
                    return self._read(key.start, create_string_buffer(0xffffffff - key.start))
		else:
                    return self._read(key.start, create_string_buffer(key.stop - key.start))
	    elif (isinstance(key, int) or isinstance(key, long)) and key >= 0x0 and key <= 0xffffffff:
                return self.read_int(key)
	    else:
                raise KeyError("Key must be a valid slice or memory address.")
		
	def __setitem__(self, key, value):
	    if (isinstance(key, int) or isinstance(key, long)) and key >= 0x0 and key <= 0xffffffff:
                self.write(key, value)
	    else:
		raise KeyError("Key must be a valid memory address.")


        def _get_regionpathinfo(self, address):
            ri = proc_regionwithpathinfo()
            result = self.libSystem.proc_pidinfo(self.pid, PROC_PIDREGIONPATHINFO, c_uint64(address), byref(ri), sizeof(ri))
            result = ri if result else None
            return result

        def get_vmem_info(self, address=0):
            info = None
            ri = self._get_regionpathinfo(address)
            if ri != None:          
                info = vmem_info(ri)
            return info


