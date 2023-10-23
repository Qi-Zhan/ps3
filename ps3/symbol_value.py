import pyvex.const as pc

class SymbolicValue(pc.IRConst):
    
    def __str__(self) -> str:
        raise NotImplementedError("You should implement this method in the subclass")
    
    def can_be_concretized(self) -> bool:
        return False

class RegSymbol(SymbolicValue):
    def __init__(self, offset) -> None:
        self.offset = offset
        self._value = f"SR({self.offset})"
    
    def __str__(self) -> str:
        return f"SR({self.offset})"
    
    def __hash__(self):
        return hash(self.offset)
    
    def __eq__(self, other):
        if isinstance(other, RegSymbol):
            return self.offset == other.offset
        return False
    
class WildCardSymbol(SymbolicValue):
    def __init__(self) -> None:
        self._value = 0
    
    def __str__(self) -> str:
        return "WildCard"
    
    def __repr__(self) -> str:
        return "WildCard"
    
    def __eq__(self, other):
        return True

class MemSymbol(SymbolicValue):
    def __init__(self, address) -> None:
        self.address = address
        self._value = f"SM({self.address})"
    
    def __str__(self) -> str:
        # return f"Mem"
        return f"Mem({self.address})"
    
    def __hash__(self):
        return hash(self.address)
    
    def __eq__(self, other):
        if isinstance(other, MemSymbol):
            return self.address == other.address
        return False

class ReturnSymbol(SymbolicValue):
    order = 0
    def __init__(self, name) -> None:
        self.name = name
        self.order = ReturnSymbol.order
        self._value = f"FakeRet({ReturnSymbol.order})"
        ReturnSymbol.order += 1
    
    def __str__(self) -> str:
        if self.name is not None:
            return f"FakeRet({self.name})"
        return "FakeRet"
    
    def __hash__(self):
        return hash(str(self))
    
    def __eq__(self, other):
        if isinstance(other, ReturnSymbol):
            if self.name is None and other.name is None:
                return True
            if self.name is not None and other.name is not None:
                return self.name == other.name
            return False
        return False
