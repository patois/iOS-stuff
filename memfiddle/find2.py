"""
experimental memory dumper for iOS
"""

import sys
from ios_vmem import *
from struct import *

pid = int(sys.argv[1])



vm = VirtualMemory(pid)
if not vm.task_suspend():
    raw_input ("could not suspend task!")
inp = raw_input("search: ")
s = struct.pack("<I",int(inp))
addr = 0
addr = vm.find(s, addr)
while addr != -1:
    vmi = vm.get_vmem_info(addr)
    path = ""
    if vmi != None:
        path = vmi.path
    print "found at %08X (%s)" % (addr, path)
    vm.seek(addr)
    #print repr(vm.read(len(s)).raw)
    y = raw_input("patch?")
    if y == "y":
        vm.write(struct.pack("<I",999999))
    addr += len(s)
    addr = vm.find(s, addr)
vm.task_resume()
