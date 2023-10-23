import pyvex.expr as pe
from simplify import simplify
from symbol_value import *


# x86_64 calling convention first 6 arguments are passed in registers
Arg2Reg = {
    "1": "rdi",
    "2": "rsi",
    "3": "rdx",
    "4": "rcx",
    "5": "r8",
    "6": "r9",
}

Arg2RegNum = [72, 64, 32, 24, 80, 88]

class Environment:
    def __init__(self) -> None:
        self.regs: dict[int, pe.IRExpr] = {}
        self.mems: dict[pe.IRExpr, pe.IRExpr] = {}
        self.tmps: dict[int, pe.IRExpr] = {} 
        
    def get_reg(self, offset: int) -> pe.IRExpr:
        if offset not in self.regs:
            self.regs[offset] = pe.Const(RegSymbol(offset)) # symbolic value
        return self.regs[offset]
    
    def set_reg(self, offset: int, value: pe.IRExpr) -> None:
        self.regs[offset] = value
    
    def get_tmp(self, offset: int) -> pe.IRExpr:
        return self.tmps[offset] # tmps must be initialized before get
    
    def set_tmp(self, offset: int, value: pe.IRExpr):
        self.tmps[offset] = value
    
    def get_mem(self, address: pe.IRExpr) -> pe.IRExpr:
        # print(f"get_mem1: {address}, simple: {simplify(address)}")
        simple_addr = simplify(address)
        splits = str(simple_addr).split()
        if len(splits) == 3:
            # print(f"get_mem2: {hex(int(splits[0]))} {splits[1]} {splits[2]}")
            if splits[1] == "+" and splits[2] == "SR(48)":
                if int(splits[0]) in self.mems:
                    return self.mems[int(splits[0])]
        if address not in self.mems:
            self.mems[address] = pe.Const(MemSymbol(address))
        return self.mems[address]

    def set_mem(self, address, value) -> None:
        simple_addr = simplify(address)
        splits = str(simple_addr).split()
        if len(splits) == 3:
            if splits[1] == "+" and splits[2] == "SR(48)":
                self.mems[int(splits[0])] = value
                return
        self.mems[address] = value
        
    def set_ret(self, name=None) -> None:
        RAX = 16
        RSP = 48
        self.set_reg(RAX, pe.Const(ReturnSymbol(name)))
        # x86_64 call will push return address to stack, so we need to pop it after call
        self.set_reg(RSP, pe.Binop("Iop_Add64", [self.get_reg(RSP), pe.Const(8)]))
        
    
    def fork(self) -> 'Environment':
        env = Environment()
        env.tmps = self.tmps.copy()
        env.regs = self.regs.copy()
        env.mems = self.mems.copy()
        return env
    
    def show_regs(self):
        for key in self.regs:
            print(f"reg{key}:", self.regs[key])

    def show_mems(self):
        for key in self.mems:
            print(f"mem {key}:", self.mems[key])
    
    def show_tmps(self):
        for key in self.tmps:
            print(f"tmp{key}:", self.tmps[key])
    
    def show(self):
        self.show_regs()
        self.show_mems()
        self.show_tmps()
