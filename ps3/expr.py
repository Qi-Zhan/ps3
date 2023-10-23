import pyvex.expr as pe
import pyvex.const as pc
from symbol_value import ReturnSymbol
from env import Environment

def reduce(expr: pe.IRExpr | pc.IRConst, env: Environment) -> pe.IRExpr:
    if not isinstance(expr, pe.IRExpr):
        if isinstance(expr, pc.IRConst):
            return expr
        print(f"{type(expr)} is not IRExpr | IRConst.")
        assert False
    # if isinstance(expr, pe.VECRET):
    #     return expr
    # if isinstance(expr, pe.GSPTR):
    #     return expr
    if isinstance(expr, pe.Binop):
        return pe.Binop(expr.op, [reduce(expr.args[0], env), reduce(expr.args[1], env)])
    if isinstance(expr, pe.Unop):
        return pe.Unop(expr.op, [reduce(expr.args[0], env)])
    # if isinstance(expr, pe.GetI):
    #     return pe.GetI(expr.descr, reduce(expr.ix, env))
    if isinstance(expr, pe.RdTmp):
        return env.get_tmp(expr.tmp)
    if isinstance(expr, pe.Get):
        return env.get_reg(expr.offset)
    if isinstance(expr, pe.Qop):
        return pe.Qop(expr.op, [reduce(arg, env) for arg in expr.args])
    if isinstance(expr, pe.Triop):
        return pe.Triop(expr.op, [reduce(arg, env) for arg in expr.args])
    if isinstance(expr, pe.Load):
        return env.get_mem(reduce(expr.addr, env))
    # if isinstance(expr, pe.ITE):
    #     return pe.ITE(reduce(expr.cond, env), reduce(expr.iftrue, env), reduce(expr.iffalse, env))
    if isinstance(expr, pe.Const):
        return expr
    if isinstance(expr, pe.CCall):
        return ReturnSymbol(name=expr.cee.name)
    if isinstance(expr, pe.ITE):
        return pe.ITE(reduce(expr.cond, env), reduce(expr.iftrue, env), reduce(expr.iffalse, env))
    print(f"{type(expr)} is not considered.")
    assert False

def contain_symbol(expr: pe.IRExpr) -> bool:
    string = str(expr)
    return "FakeReturn" in string or "Mem" in string or "SR" in string

class Expression:
    def __init__(self, expr: pe.IRExpr):
        self.expr = expr
    
    @classmethod
    def construct(expr: pe.IRExpr):
        if isinstance(expr, pe.VECRET):
            return VECRET(expr)
        elif isinstance(expr, pe.GSPTR):
            return GSPTR(expr)
        elif isinstance(expr, pe.GetI):
            return GetI(expr)
        elif isinstance(expr, pe.RdTmp):
            return RdTmp(expr)
        elif isinstance(expr, pe.Get):
            return Get(expr)
        elif isinstance(expr, pe.Qop):
            return Qop(expr)
        elif isinstance(expr, pe.Triop):
            return Triop(expr)
        elif isinstance(expr, pe.Binop):
            return Binop(expr)
        elif isinstance(expr, pe.Unop):
            return Unop(expr)
        elif isinstance(expr, pe.Load):
            return Load(expr)
        elif isinstance(expr, pe.ITE):
            return ITE(expr)
        elif isinstance(expr, pe.CCall):
            return CCall(expr)
        else:
            raise NotImplementedError("You should implement this method in the subclass")

    def __str__(self) -> str:
        return str(self.expr)
    
    def reduce(self, env: Environment) -> "Expression":
        self.expr.replace_expression()
        raise NotImplementedError("You should implement this method in the subclass")
    
class VECRET(Expression):
    def __init__(self, expr: pe.VECRET):
        self.expr = expr
    
    def reduce(self, env: Environment):
        return self
        
class GSPTR(Expression):
    def __init__(self, expr: pe.IRExpr):
        self.expr = expr
    pass

class GetI(Expression):
    pass

class RdTmp(Expression):
    pass

class Get(Expression):
    pass

class Qop(Expression):
    pass

class Triop(Expression):
    pass

class Binop(Expression):
    pass

class Unop(Expression):
    pass

class Load(Expression):
    pass

class ITE(Expression):
    pass

class CCall(Expression):
    pass

class Const(Expression):
    pass
