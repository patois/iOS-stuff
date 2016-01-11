from ctypes import *
from ctypes.util import find_library
import sys, struct


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



libSys = CDLL(find_library("System"))

pid = int(sys.argv[1])
ri = proc_regionwithpathinfo()

PROC_PIDREGIONPATHINFO = 8

paths = ["/Library/","/usr/","/System/"]
errors = []
addresses = []
#findval = struct.pack("<I", int(sys.argv[2]))

while True:
    s = raw_input("cmd: ").split()
    print s
    if s[0] == "ff":
        addr = 0
        addresses = []
        findval = struct.pack("<I", int(s[1]))
        while libSys.proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, c_uint64(addr), byref(ri), sizeof(ri)):
            # filter
            if not any([v for v in paths if v in ri.vip.path]):
                #if True:
                p = mp = ""
                p += "r" if ri.prinfo.protection & VM_PROT_READ else "-"
                p += "w" if ri.prinfo.protection & VM_PROT_WRITE else "-"
                p += "x" if ri.prinfo.protection & VM_PROT_EXECUTE else "-"

                mp += "r" if ri.prinfo.max_protection & VM_PROT_READ else "-"
                mp += "w" if ri.prinfo.max_protection & VM_PROT_WRITE else "-"
                mp += "x" if ri.prinfo.max_protection & VM_PROT_EXECUTE else "-"        

                if (ri.prinfo.protection & VM_PROT_WRITE) and (ri.prinfo.protection & VM_PROT_READ):
                    print ri.vip.path
                    print "%X - %X (%X) [%s|%s]\n" % (ri.prinfo.address, ri.prinfo.address + ri.prinfo.size, ri.prinfo.size, p, mp)
                    t = c_uint()
                    libSys.task_for_pid(libSys.mach_task_self(), pid, byref(t))
                    count = c_uint(4)
                    buf = create_string_buffer(ri.prinfo.size)
                    libSys.vm_read_overwrite(t.value, ri.prinfo.address, ri.prinfo.size, byref(buf), byref(count))
                    if count.value != ri.prinfo.size:
                        errors.append("############# ERR")
                    #f = open("/private/var/root/dumps/%X" % ri.prinfo.address, "wb")
                    #f.write(buf.raw)
                    #f.close()
                    p = 0
                    p = buf.raw.find(findval)
                    while (p != -1):
                        addresses.append(ri.prinfo.address + p)
                        p = buf.raw[p:].find(findval, p+1)
            addr = ri.prinfo.address + ri.prinfo.size


        #for e in errors:
        #    print e
    elif s[0] == "p":
        a = int(s[1],16)
        v = c_int(int(s[2]))

        t = c_uint()
        libSys.task_for_pid(libSys.mach_task_self(), pid, byref(t))
        print "%X -> %d" % (a, v.value)
        res = libSys.vm_write(t.value, a, byref(v), 4)
        if res == 0:
            print "patch successful!"

    elif s[0] == "fn":
        findval = struct.pack("<I", int(s[1]))
        t = c_uint()
        libSys.task_for_pid(libSys.mach_task_self(), pid, byref(t))

        for a in addresses:
            count = c_uint32(4)
            buf = create_string_buffer(4)
            res = libSys.vm_read_overwrite(t.value, a, c_uint(4), byref(buf), byref(count))
            if res > 0 or buf.raw != findval:
                print hex(a), count.value, repr(buf.raw), repr(findval)
                addresses.remove(a)

    elif s[0] == "q":
        break
    elif s[0] == "mod":
        addr = 0
        addresses = []
        findaddr = int(s[1],16)
        while libSys.proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, c_uint64(addr), byref(ri), sizeof(ri)):
            if findaddr >= ri.prinfo.address and findaddr < ri.prinfo.address + ri.prinfo.size:
                print "%08X - %08X : %s" % (ri.prinfo.address, ri.prinfo.address + ri.prinfo.size, ri.vip.path)
                break
            addr = ri.prinfo.address + ri.prinfo.size

        
    elif s[0] == "l":
        for a in addresses:
            print "%08X" % a
