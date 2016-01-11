"""
memory dumper for iOS
dumps memory regions that are at least readable and writable to a given path
"""

import sys
from ios_vmem import *

pid = int(sys.argv[1])
path = sys.argv[2]


vm = VirtualMemory(pid)
vm.task_suspend()

mem = vm.get_vmem_info(0)
readerrs = []
while mem != None:
    if mem.writable and mem.readable and (not mem.sysmodule):
        dst = os.path.join(path, "%08X" % mem.address)
        if len(mem.path):
            print mem.path
        print "%08X - %08X (%X) [%s]\n" % (mem.address, mem.endaddress, mem.size, mem.rwx)
        if vm.dump(mem.address, mem.size, dst):
            pass
        else:
            readerrs.append(mem.address)
    address = mem.address + mem.size
    mem = vm.get_vmem_info(address)

vm.task_resume()
print "%d read error%s encountered." % (len(readerrs), "s" if len(readerrs)!=1 else "")
for addr in readerrs:
    print "%08X" % addr
