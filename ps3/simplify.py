import pyvex.expr as pe
import pyvex.const as pc
from symbol_value import RegSymbol, ReturnSymbol, MemSymbol
import z3

mapfunction = z3.Function("Mem", z3.BitVecSort(64), z3.BitVecSort(64))


def simplify(expr: pe.IRExpr):
    if isinstance(expr, int) or isinstance(expr, str) or expr == None:
        return expr
    if isinstance(expr, list):
        return [simplify(e) for e in expr]
    return simplify_z3(to_z3(expr))


def equal(expr1: pe.IRExpr, expr2: pe.IRExpr) -> bool:
    if isinstance(expr1, int) or isinstance(expr1, str):
        return expr1 == expr2
    if isinstance(expr1, list):
        if not isinstance(expr2, list):
            return False
        if len(expr1) != len(expr2):
            return False
        for i in range(len(expr1)):
            if not equal(expr1[i], expr2[i]):
                return False
        return True
    return equal_z3(to_z3(expr1), to_z3(expr2))


def to_z3(expr):
    try:
        return to_z3_true(expr)
    except Exception as e:
        print(f"Error converting {expr}: {e}")
        return z3.BitVecVal(0, 64)


def to_z3_true(expr: pe.IRExpr | pc.IRConst | int) -> z3.ExprRef:
    if isinstance(expr, int):
        return z3.BitVecVal(expr, 64)
    if isinstance(expr, pc.IRConst):
        if isinstance(expr, RegSymbol):
            return z3.BitVec(str(expr), 64)
        if isinstance(expr, MemSymbol):
            # use the memory address as the variable name
            return mapfunction(to_z3(expr.address))
        if isinstance(expr, ReturnSymbol):
            return z3.BitVec(str(expr), 64)
        return z3.BitVecVal(expr._value, 64)
    if isinstance(expr, pe.Const):
        return to_z3(expr.con)
    if isinstance(expr, pe.Unop):
        if expr.op.find("to") != -1:
            if expr.op == "Iop_1Uto64":  # 1U means bool
                return z3.If(to_z3(expr.args[0]), z3.BitVecVal(0, 64), z3.BitVecVal(1, 64))
            return to_z3(expr.args[0])
        match expr.op:
            case "Iop_Not32" | "Iop_Not64" | "Iop_Not8" | "Iop_Not16" | "Iop_Not":
                inner = to_z3(expr.args[0])
                if isinstance(inner, z3.BitVecRef):
                    return z3.If(inner == z3.BitVecVal(0, 64), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                return z3.Not(inner)
            case _:
                return z3.BitVecVal(0, 64)
                raise Exception(f"{expr.op} Unop not considered")
    if isinstance(expr, pe.CCall):
        raise Exception(f"{expr} CCall not considered")
    if isinstance(expr, pe.ITE):
        cond = to_z3(expr.cond)
        if isinstance(cond, z3.BitVecRef):
            return z3.If(cond == 0, to_z3(expr.iffalse), to_z3(expr.iftrue))
        return z3.If(cond, to_z3(expr.iftrue), to_z3(expr.iffalse))
    if isinstance(expr, pe.Binop):
        match expr.op:
            case "Iop_Add32" | "Iop_Add64" | "Iop_Add8" | "Iop_Add16":
                return to_z3(expr.args[0]) + to_z3(expr.args[1])
            case "Iop_Sub32" | "Iop_Sub64" | "Iop_Sub8" | "Iop_Sub16":
                return to_z3(expr.args[0]) - to_z3(expr.args[1])
            case "Iop_Mul32" | "Iop_Mul64" | "Iop_Mul8" | "Iop_Mul16":
                return to_z3(expr.args[0]) * to_z3(expr.args[1])
            case "Iop_Div32" | "Iop_Div64" | "Iop_Div8" | "Iop_Div16":
                return z3.UDiv(to_z3(expr.args[0]), to_z3(expr.args[1]))
            case "Iop_And32" | "Iop_And64" | "Iop_And8" | "Iop_And16" | "Iop_AndV128" | "Iop_AndV256" | "Iop_AndV512":
                z31 = to_z3(expr.args[0])
                z32 = to_z3(expr.args[1])
                if isinstance(z31, z3.BoolRef) and isinstance(z32, z3.BoolRef):
                    return z3.And(z31, z32)
                return z31 & z32
            case "Iop_Or32" | "Iop_Or64" | "Iop_Or8" | "Iop_Or16" | "Iop_OrV128" | "Iop_OrV256" | "Iop_OrV512":
                z31 = to_z3(expr.args[0])
                z32 = to_z3(expr.args[1])
                if isinstance(z31, z3.BoolRef) and isinstance(z32, z3.BoolRef):
                    return z3.Or(z31, z32)
                return z31 | z32
            case "Iop_Shl32" | "Iop_Shl64" | "Iop_Shl8" | "Iop_Shl16":
                return to_z3(expr.args[0]) << to_z3(expr.args[1])
            case "Iop_Shr32" | "Iop_Shr64" | "Iop_Shr8" | "Iop_Shr16":
                return z3.LShR(to_z3(expr.args[0]), to_z3(expr.args[1]))
            case "Iop_Sar32" | "Iop_Sar64" | "Iop_Sar8" | "Iop_Sar16":
                return to_z3(expr.args[0]) >> to_z3(expr.args[1])
            case "Iop_Xor32" | "Iop_Xor64" | "Iop_Xor8" | "Iop_Xor16":
                return to_z3(expr.args[0]) ^ to_z3(expr.args[1])
            case "Iop_CmpEQ32" | "Iop_CmpEQ64" | "Iop_CmpEQ8" | "Iop_CmpEQ16":
                to_z31 = to_z3(expr.args[0])
                to_z32 = to_z3(expr.args[1])
                return to_z31 == to_z32
            case "Iop_CmpNE32" | "Iop_CmpNE64" | "Iop_CmpNE8" | "Iop_CmpNE16" | "Iop_CasCmpNE32" | "Iop_CasCmpNE64" | "Iop_CasCmpNE128" | "Iop_CasCmpNE256" | "Iop_CasCmpNE512":
                value = to_z3(expr.args[0]) != to_z3(expr.args[1])
                return value
            case "Iop_CmpLT32S" | "Iop_CmpLT64S" | "Iop_CmpLT8S" | "Iop_CmpLT16S":
                value = to_z3(expr.args[0]) < to_z3(expr.args[1])
                return value
            case "Iop_CmpLT32U" | "Iop_CmpLT64U" | "Iop_CmpLT8U" | "Iop_CmpLT16U":
                value = z3.ULT(to_z3(expr.args[0]), to_z3(expr.args[1]))
                return value
            case "Iop_CmpLE32S" | "Iop_CmpLE64S" | "Iop_CmpLE8S" | "Iop_CmpLE16S":
                value = to_z3(expr.args[0]) <= to_z3(expr.args[1])
                return value
            case "Iop_CmpLE32U" | "Iop_CmpLE64U" | "Iop_CmpLE8U" | "Iop_CmpLE16U":
                value = z3.ULE(to_z3(expr.args[0]), to_z3(expr.args[1]))
                return value
            case "Iop_CmpGT32S" | "Iop_CmpGT64S" | "Iop_CmpGT8S" | "Iop_CmpGT16S":
                value = to_z3(expr.args[0]) > to_z3(expr.args[1])
                return value
            case "Iop_CmpGT32U" | "Iop_CmpGT64U" | "Iop_CmpGT8U" | "Iop_CmpGT16U":
                value = z3.UGT(to_z3(expr.args[0]), to_z3(expr.args[1]))
                return value
            case "Iop_CmpGE32S" | "Iop_CmpGE64S" | "Iop_CmpGE8S" | "Iop_CmpGE16S":
                value = to_z3(expr.args[0]) >= to_z3(expr.args[1])
                return value
            case "Iop_CmpGE32U" | "Iop_CmpGE64U" | "Iop_CmpGE8U" | "Iop_CmpGE16U":
                value = z3.UGE(to_z3(expr.args[0]), to_z3(expr.args[1]))
                return value
            case "Iop_DivModU64to32" | "Iop_DivModS64to32" | "Iop_DivModU128to64" | "Iop_DivModS128to64":
                # return z3.Concat(z3.UDiv(to_z3(expr.args[0]) , to_z3(expr.args[1])) , z3.UMod(to_z3(expr.args[0]) , to_z3(expr.args[1])))
                return z3.BitVecVal(0, 64)
            case "Iop_32HLto64" | "Iop_64HLto128" | "Iop_64HLtoV128" | "Iop_128HLtoV128":
                return z3.Concat(to_z3(expr.args[0]), to_z3(expr.args[1]))
            case "Iop_MullU32":
                return to_z3(expr.args[0]) * to_z3(expr.args[1])
            case "Iop_ExpCmpNE64":
                return to_z3(expr.args[0]) != to_z3(expr.args[1])
            case _:
                print(f"{expr.op} is not a valid op type")
    return z3.BitVecVal(0, 64)
    assert False, (f"{expr}, {type(expr)} is not considered")


def simplify_z3(expr):
    return z3.simplify(expr)

def equal_z3(expr1, expr2):
    expr1_simplify = simplify_z3(expr1)
    expr2_simplify = simplify_z3(expr2)
    result = z3.eq(expr1_simplify, expr2_simplify)
    if result:
        return True
    else:
        # use prove to check if the two expr are equal semanticly
        if 'If' in str(expr1_simplify) and 'If' in str(expr2_simplify):
            try:
                return prove(expr1_simplify == expr2_simplify)
            except Exception:
                return False
        return False


def expr_similarity(expr1, expr2):
    expr1_simplify = simplify_z3(expr1)
    expr2_simplify = simplify_z3(expr2)
    # print(expr1, expr2, result)
    raise NotImplementedError("expr_similarity")


def prove(f):
    s = z3.Solver()
    s.add(z3.Not(f))
    if s.check() == z3.unsat:
        return True
    else:
        return False
