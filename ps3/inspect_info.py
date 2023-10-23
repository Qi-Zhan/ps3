from simplify import simplify, equal


class InspectInfo:
    def __init__(self, ins) -> None:
        self.ins = ins

    def __str__(self) -> str:
        if isinstance(self.ins, tuple):
            if len(self.ins) == 3:
                return f"{self.ins[0]}: {str(simplify(self.ins[1]))} = {str(simplify(self.ins[2]))}"
            if len(self.ins) == 2:
                return f"{str(simplify(self.ins[0]))}: {str(simplify(self.ins[1]))}"
        else:
            return str(self.ins)

    def __repr__(self) -> str:
        return str(self)

    # python set will compare hash value first, then compare __eq__
    # so we need to make sure that two InspectInfo with same ins must have same hash value
    def __hash__(self) -> int:
        return hash(self.ins[0])

    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, InspectInfo):
            if isinstance(self.ins, tuple) and isinstance(__o.ins, tuple):
                if len(self.ins) != len(__o.ins):
                    return False
                for i in range(len(self.ins)):
                    if not equal(self.ins[i], __o.ins[i]):
                        return False
                return True
            else:
                print(self)
                assert False, "Not implemented"
        return False
