import pyvex.stmt as ps

from pyvex.expr import IRExpr
from expr import reduce
from env import Environment
from inspect_info import InspectInfo

# A wrapper for pyvex.stmt
class Statement: 
    
    def __init__(self, stmt: ps.IRStmt) -> None:
        self.stmt = stmt
    
    @classmethod
    def construct(cls, stmt: ps.IRStmt):
        if isinstance(stmt, ps.IMark):
            return IMark(stmt)
        elif isinstance(stmt, ps.Put):
            return Put(stmt)
        elif isinstance(stmt, ps.PutI):
            return PutI(stmt)
        elif isinstance(stmt, ps.Store):
            return Store(stmt)
        elif isinstance(stmt, ps.StoreG):
            return StoreG(stmt)
        elif isinstance(stmt, ps.WrTmp):
            return WrTmp(stmt)
        elif isinstance(stmt, ps.Exit):
            return Exit(stmt)
        elif isinstance(stmt, ps.NoOp):
            return NoOp(stmt)
        elif isinstance(stmt, ps.AbiHint):
            return AbiHint(stmt)
        elif isinstance(stmt, ps.CAS):
            return CAS(stmt)            
        elif isinstance(stmt, ps.Dirty):
            return Dirty(stmt)
        elif isinstance(stmt, ps.MBE):
            return MBE(stmt)
        elif isinstance(stmt, ps.LoadG):
            return LoadG(stmt)
        elif isinstance(stmt, ps.LLSC):
            return LLSC(stmt)
        assert False, f"Unknown statement type {type(stmt)}"

    def __str__(self) -> str:
        return str(self.stmt)
    
    def __repr__(self) -> str:
        return str(self.stmt)
    
    def simulate(self, env: Environment, inspect: bool = False) -> None:
        raise NotImplementedError("You should implement this method in the subclass")
    
    def inspect(self, env: Environment) -> None:
        raise NotImplementedError("You should implement this method in the subclass") 

class IMark(Statement):
    def __init__(self, stmt: ps.IMark) -> None:
        self.stmt = stmt
        
    def simulate(self, env: Environment, inspect: bool = False) -> None:
        # if 0x54aaa1 <= self.stmt.addr <= 0x54aab3:
        #     print(f"here {hex(self.stmt.addr)}")
        #     env.show()
        #     input()
        pass
    
class Put(Statement):
    def __init__(self, stmt: ps.Put) -> None:
        self.stmt = stmt

    def simulate(self, env: Environment, inspect: bool = False) -> None | InspectInfo:
        data = reduce(self.stmt.data, env)
        env.set_reg(self.stmt.offset, data)
        if inspect:
            # if write to rip, then ignore it
            if self.stmt.offset != 184: 
                return InspectInfo(("Put", self.stmt.offset, data))

class PutI(Statement):
    def __init__(self, stmt: ps.PutI) -> None:
        self.stmt = stmt

    def simulate(self, env: Environment, inspect: bool = False) -> None:
        raise NotImplementedError

class Store(Statement):
    def __init__(self, stmt: ps.Store) -> None:
        self.stmt = stmt
    
    def simulate(self, env: Environment, inspect: bool = False) -> None | InspectInfo:
        data = reduce(self.stmt.data, env)
        addr = reduce(self.stmt.addr, env)
        env.set_mem(addr, data)
        if inspect:
            return InspectInfo(("Store", addr, data))

class StoreG(Statement):
    def __init__(self, stmt: ps.StoreG) -> None:
        self.stmt = stmt
        
class WrTmp(Statement):
    def __init__(self, stmt: ps.WrTmp) -> None:
        self.stmt = stmt
        
    def simulate(self, env: Environment, inspect: bool = False) -> None:
        data = reduce(self.stmt.data, env)
        env.set_tmp(self.stmt.tmp, data)
        
class Exit(Statement):
    def __init__(self, stmt: ps.Exit) -> None:
        self.stmt = stmt
    
    def simulate(self, env: Environment, inspect: bool = False) -> IRExpr:
        guard = reduce(self.stmt.guard, env)
        dst = reduce(self.stmt.dst, env)
        offsIP = self.stmt.offsIP
        if isinstance(offsIP, int):
            env.set_reg(offsIP, dst)
        else:
            assert False, f"Unsupported type {type(offsIP)}"
        env.set_reg(offsIP, dst)
        return guard

class CAS(Statement):
    def __init__(self, stmt: ps.CAS) -> None:
        self.stmt = stmt
    
    def simulate(self, env: Environment, inspect: bool = False) -> None:
        pass

class Dirty(Statement):
    def __init__(self, stmt: ps.Dirty) -> None:
        self.stmt = stmt
    
    def simulate(self, env: Environment, inspect: bool = False) -> None:
        print("Dirty")
        breakpoint()

class MBE(Statement):
    def __init__(self, stmt: ps.MBE) -> None:
        self.stmt = stmt
    
    def simulate(self, env: Environment, inspect: bool = False) -> None:
        pass

class LoadG(Statement):
    def __init__(self, stmt: ps.LoadG) -> None:
        self.stmt = stmt
    
    def simulate(self, env: Environment, inspect: bool = False) -> None:
        print("LoadG")
        breakpoint()

class LLSC(Statement):
    def __init__(self, stmt: ps.LLSC) -> None:
        self.stmt = stmt
    
    def simulate(self, env: Environment, inspect: bool = False) -> None:
        print("LLSC")
        breakpoint()
    
class NoOp(Statement):
    def __init__(self, stmt: ps.NoOp) -> None:
        self.stmt = stmt
        
    def simulate(self, env: Environment, inspect: bool = False) -> None:
        pass

class AbiHint(Statement):
    def __init__(self, stmt: ps.AbiHint) -> None:
        self.stmt = stmt
    
    def simulate(self, env: Environment, inspect: bool = False) -> None:
        pass
