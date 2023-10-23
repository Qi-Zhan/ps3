import angr
import sys
from log import *
from io import StringIO
import re
import pyvex.stmt as ps
import pyvex.expr as pe
import stmt
from env import Environment, Arg2RegNum
from inspect_info import InspectInfo
from diff_parser import Patterns
from symbol_value import WildCardSymbol


class FunctionNotFound(Exception):
    pass


logger = get_logger(__name__)
logger.setLevel(INFO)

sys.setrecursionlimit(10000)


def hexl(l):
    return [hex(x) for x in l]


class State:
    def __init__(self, node: angr.knowledge_plugins.cfg.cfg_node.CFGNode, env: Environment) -> None:
        self.node = node
        self.env = env
        self.addrs = []  # addrs that travel
        self.inspect = {}
        self.inspect_patterns = {}

    def fork(self) -> "State":
        state = State(self.node, self.env.fork())
        state.addrs = self.addrs.copy()
        state.inspect = self.inspect.copy()
        state.inspect_patterns = self.inspect_patterns
        return state

    def __str__(self) -> str:
        return f"State({hex(self.node.addr)})"

    def __repr__(self) -> str:
        return self.__str__()


class Simulator:
    def __init__(self, proj: angr.Project) -> None:
        self.proj = proj

    def _init_function(self, funcname: str):
        symbol = self.proj.loader.find_symbol(funcname)
        if symbol is None:
            raise FunctionNotFound(
                f"symbol {funcname} not found in binary {self.proj}")
        self.funcname = funcname
        cfg = self.proj.analyses.CFGFast(
            regions=[(symbol.rebased_addr, symbol.rebased_addr + symbol.size)], normalize=True)
        function = None
        for func in cfg.functions:
            if cfg.functions[func].name == funcname:
                function = cfg.functions[func]
                break
        assert function is not None
        self.graph = cfg.graph
        self.cfg = cfg
        self.function = function
        self._init_map()

    def _init_map(self):
        self.node2IR: dict[angr.knowledge_plugins.cfg.cfg_node.CFGNode,
                           list[stmt.Statement]] = {}
        self.addr2IR = {}
        addr = None

        for block in self.function.blocks:
            for statement in block.vex.statements:
                if isinstance(statement, ps.IMark):
                    addr = statement.addr
                stmtwrapper = stmt.Statement.construct(statement)
                if addr not in self.addr2IR:
                    self.addr2IR[addr] = []
                self.addr2IR[addr].append(stmtwrapper)

        for node in self.graph.nodes:
            self.node2IR[node] = []
            addrs = node.instruction_addrs
            for addr in addrs:
                if addr not in self.addr2IR:
                    continue
                    assert False, f"addr {hex(addr)} not in addr2IR"
                self.node2IR[node].extend(self.addr2IR[addr])

        self.IR2addr = {}
        for addr in self.addr2IR.keys():
            IRs = self.addr2IR[addr]
            for IR in IRs:
                self.IR2addr[IR] = addr

        self.addr2Node = {}
        for node in self.cfg.nodes():
            self.addr2Node[node.addr] = node

    def _reachable_set(self, addrs: set[int]) -> set:
        endnodes = []
        for addr in addrs:
            if addr not in self.addr2Node:
                continue
            endnodes.append(self.addr2Node[addr])

        predecessors = {}
        for node in self.cfg.nodes():
            predecessors[node] = []

        for node in self.cfg.nodes():
            for succ, _ in node.successors_and_jumpkinds(False):
                predecessors[succ].append(node)

        queue = list(endnodes)
        visit = set()
        while len(queue) > 0:
            node = queue.pop()
            if node.addr in visit:
                continue
            visit.add(node.addr)
            queue.extend(predecessors[node])
        # print(visit)
        return visit

    def _reduce_addresses_by_basicblock(self, address: list[int]) -> set[int]:
        l = list(self.function.blocks)
        result = set()
        for addr in address:
            for block in l:
                if addr in block.instruction_addrs:
                    result.add(block.addr)
                    break
        return result

    def generate_forall_bb(self, funcname: str, dic) -> dict:
        self._init_function(funcname)
        all_addrs = []
        collect = {}
        for block in self.function.blocks:
            all_addrs.extend(block.instruction_addrs)
        self.inspect_addrs = all_addrs
        start_node = self.cfg.get_any_node(self.function.addr)
        init_state = State(start_node, Environment())
        reduce_addr = set(self._reduce_addresses_by_basicblock(all_addrs))
        # based on basic block inspect
        init_state.inspect = {addr: {} for addr in reduce_addr}
        init_state.inspect_patterns = dic
        queue = [init_state]
        visit = set()
        while len(queue) > 0:  # DFS
            state = queue.pop()
            if state.node.addr in visit:
                continue
            result = self._simulateBB(state)
            if isinstance(result, list):  # fork
                visit.update(result[0].addrs)
                queue.extend(result[1:])
            else:  # state run to the end
                visit.update(result.addrs)
                collect.update(result.inspect)
        return collect

    def generate(self, funcname: str, addresses: list[int], patterns) -> dict:
        if addresses[0] < self.proj.loader.main_object.min_addr:
            addresses = [(addr + self.proj.loader.main_object.min_addr)
                         for addr in addresses]
        self._init_function(funcname)
        trace = {}
        reduce_addr = set(self._reduce_addresses_by_basicblock(addresses))
        reachable = self._reachable_set(reduce_addr)
        start_node = self.cfg.get_any_node(self.function.addr)
        self.inspect_addrs = addresses
        init_state = State(start_node, Environment())
        # based on basic block inspect
        init_state.inspect = {addr: {} for addr in reduce_addr}
        init_state.inspect_patterns = patterns
        queue = [init_state]
        visit = set()
        while len(queue) > 0:  # DFS
            # print(hexl(visit))
            state = queue.pop()
            if state.node.addr not in reachable:
                continue
            if state.node.addr in visit:
                continue
            # logger.debug(f"Now begin {hex(state.node.addr)}")
            result = self._simulateBB(state, step_one=True)
            if isinstance(result, list):  # fork
                visit.update(result[0].addrs)
                trace.update(result[0].inspect)
                queue.extend(result)
            # else: # state run to the end
            #     if result.node.addr in reduce_addr:
            #         breakpoint()
            #     visit.update(result.addrs)
            #     trace.update(result.inspect)
            #     queue.append(result)
        return trace

    def _simulateBB(self, state: State, step_one=False) -> list[State] | State:
        while 1:
            state.addrs.append(state.node.addr)
            # state.env.show_mems()
            # state.env.show_regs()
            # a = state.node.block.vex._pp_str()
            # print(a)
            # for stmt in self.node2IR[state.node]:
            #     print(stmt)
            # input()
            for stmt in self.node2IR[state.node]:
                machine_addr = self.IR2addr[stmt]
                if machine_addr in self.inspect_addrs:
                    # when Exit stmt, return guard, else return tuple) else return None
                    cond = stmt.simulate(state.env, True)
                    basicblock_addr = state.node.addr
                    assert basicblock_addr in state.inspect
                    block = state.inspect[basicblock_addr]
                    if machine_addr not in block:
                        block[machine_addr] = []
                    if isinstance(cond, InspectInfo):
                        block[machine_addr].append(cond)
                    elif isinstance(cond, pe.IRExpr):  # guard it
                        block[machine_addr].append(
                            InspectInfo(("Condition", cond)))
                else:
                    cond = stmt.simulate(state.env)
            length = len(state.node.successors_and_jumpkinds(False))
            if length == 0:
                return state
            if length == 1:
                succ, jump = state.node.successors_and_jumpkinds(False)[0]
                if jump == "Ijk_Boring":
                    state.node = succ  # maybe exist condition even length == 1
                # elif jump == "Ijk_Call":
                #     output_stream = StringIO()
                #     sys.stdout = output_stream
                #     state.node.block.pp()
                #     output =  output_stream.getvalue()
                #     sys.stdout = sys.__stdout__
                #     breakpoint()
                #     state.node = succ
                #     state.env.set_ret()
                #     state.node = succ
                #     state.env.set_ret()
                elif jump == "Ijk_FakeRet":
                    output_stream = StringIO()
                    sys.stdout = output_stream
                    state.node.block.pp()
                    output = output_stream.getvalue()
                    sys.stdout = sys.__stdout__
                    # print(output)
                    # breakpoint()
                    if "call" in output:
                        call_name = output.split(
                            "\n")[-2].split("\t")[-1].split(" ")[-1]
                        # remove color in call_name
                        call_name = re.sub(r"\x1b\[[0-9;]*m", "", call_name)
                        if not call_name.startswith("0x"):
                            if call_name in state.inspect_patterns:  # collect all call
                                basicblock_addr = state.node.addr
                                if basicblock_addr in state.inspect:
                                    args = []
                                    # args number
                                    argnum = state.inspect_patterns[call_name][0]
                                    wild = state.inspect_patterns[call_name][1]
                                    for i in range(argnum):
                                        if wild[i]:
                                            args.append(WildCardSymbol())
                                        else:
                                            args.append(
                                                state.env.get_reg(Arg2RegNum[i]))
                                    info = InspectInfo(
                                        ("Call", call_name, args))
                                    block = state.inspect[basicblock_addr]
                                    if machine_addr not in block:
                                        block[machine_addr] = []
                                    block[machine_addr].append(info)
                            state.env.set_ret(call_name)
                            state.node = succ
                        else:
                            state.env.set_ret()
                            state.node = succ
                    else:
                        state.env.set_ret()
                        state.node = succ
                else:
                    logger.critical(f"NotImplementedError {jump}")
                    state.node = succ
                if step_one:
                    return [state]
            else:  # length > 1, fork
                states = [state]
                try:
                    condition = state.node.block.vex.next.constants[0].value
                except:
                    condition = None
                for succ, jump in state.node.successors_and_jumpkinds(False):
                    # print(f"{succ} {jump}")
                    if jump == "Ijk_Boring":
                        # assert cond is not None
                        newstate = state.fork()
                        newstate.node = succ
                        states.append(newstate)
                    elif jump == "Ijk_Call":
                        # for succ, jump in state.node.successors_and_jumpkinds(False):
                        #     print(f"555 {succ} {jump}")
                        newstate = state.fork()
                        newstate.env.set_ret()
                        newstate.node = succ
                        states.append(newstate)
                    elif jump == "Ijk_FakeRet":
                        # state.node.block.pp()
                        # state.node.block.vex.pp()
                        # print(succ, jump)
                        # input()
                        newstate = state.fork()
                        newstate.env.set_ret()
                        newstate.node = succ
                        states.append(newstate)
                    else:
                        logger.critical(f"NotImplementedError {jump}")
                        continue
                return states


class Signature:
    def __init__(self, collect: dict, funcname: str, state: str, patterns) -> None:
        self.collect = collect
        self.funcname = funcname
        self.state = state
        self.patterns = patterns

    @classmethod
    def from_add(cls, collect: dict, funcname: str, state: str, patterns) -> "Signature":
        return cls(collect, funcname, state, patterns)

    @classmethod
    def from_remove(cls, collect: dict, funcname: str, state: str, patterns) -> "Signature":
        return cls(collect, funcname, state, patterns)

    @classmethod
    def from_modify(cls, collect_vuln: dict, collect_patch: dict, funcname: str, add_pattern, remove_pattern) -> "Signature":
        return cls([collect_vuln, collect_patch], funcname, "modify", [remove_pattern, add_pattern])

    def _clean(self, collect):
        collect_copy = collect.copy()
        for site in collect_copy:
            string = str(site)
            if string.find("FakeRet") == -1 and string.find("Mem") == -1 and string.find("SR") == -1:
                collect.remove(site)
        collect_copy = collect.copy()
        conds = []
        others = []
        for site in reversed(collect_copy):
            if site.ins[0] == "Condition":
                string = str(site.ins[1])
                conds.append(string)
            elif site.ins[0] == "Store":
                string = str(site.ins[2])
                if string in others:
                    collect.remove(site)
                    continue
                for cond in conds:
                    if string in cond:
                        collect.remove(site)
                        break
                others.append(string)
            elif site.ins[0] == "Call":
                for arg in site.ins[2]:
                    others.append(str(arg))
            elif site.ins[0] == "Put":
                string = str(site.ins[2])
                # FakeRet with name, we cannot remove it
                if "FakeRet" in string and len(string) > len("FakeRet()"):
                    continue
                if string in others:
                    collect.remove(site)
                    continue
                for cond in conds:
                    if string in cond:
                        collect.remove(site)
                        break
                others.append(string)
        return collect

    def serial(self) -> list | tuple[list, list]:
        if self.state == "modify":
            return (self._serial(self.collect[0]), self._serial(self.collect[1]))
        else:
            return self._serial(self.collect)

    def _serial(self, collect) -> tuple[list, list]:
        l = []
        for bb in collect.keys():
            for addr_or_cons in collect[bb].keys():
                if addr_or_cons == "Constraints":
                    pass
                else:
                    for single_site in collect[bb][addr_or_cons]:
                        l.append(single_site)
        return self._clean(l), []

    def __str__(self) -> str:
        return f"{self.funcname} {self.state} {self.collect}"

    def show(self) -> None:
        if self.state == "modify":
            self._show(self.collect[0], "vuln")
            self._show(self.collect[1], "patch")
        else:
            self._show(self.collect, self.state)

    def _show(self, collect, type="") -> None:
        print("=========================================", type)
        ser = self._serial(collect)
        for single_site in ser[0]:
            print(single_site)
        print("=========================================")


def valid_sig(sigs: list[Signature]):
    exists_modify = False
    for sig in sigs:
        if sig.state == "modify":
            exists_modify = True
            break
    if exists_modify:
        new_sigs = []
        for sig in sigs:
            if sig.state == "modify":
                add, remove = sig.serial()
                add = set(add[0])
                remove = set(remove[0])
                # breakpoint()
                if add.issuperset(remove) or remove.issuperset(add):
                    continue
                new_sigs.append(sig)
        return new_sigs
    return sigs


def handle_pattern(patterns: Patterns | list[Patterns]) -> dict:
    def _handle_pattern(patterns: Patterns) -> dict:
        dic = {}
        for pattern in patterns.patterns:
            if pattern.pattern == "If":
                pass
            if pattern.pattern == "Call":
                dic[pattern.name] = [pattern.number, pattern.wildcard]
        return dic
    if isinstance(patterns, Patterns):
        return _handle_pattern(patterns)
    else:
        dic = {}
        for pa in patterns:
            dic.update(_handle_pattern(pa))
        return dic


class Generator:

    def __init__(self, vuln_proj: angr.Project, patch_proj: angr.Project) -> None:
        self.vuln_proj = Simulator(vuln_proj)
        self.patch_proj = Simulator(patch_proj)

    @classmethod
    def from_binary(cls, vuln_path: str, patch_path: str):
        proj1 = angr.Project(vuln_path, load_options={'auto_load_libs': False})
        proj2 = angr.Project(patch_path, load_options={
                             'auto_load_libs': False})
        assert proj1.loader.main_object.min_addr == proj2.loader.main_object.min_addr
        return Generator(proj1, proj2)

    def generate(self, funcname: str, addresses: list[int], state: str, patterns: Patterns) -> dict:
        patterns_ = handle_pattern(patterns)
        try:
            if state == "vuln":
                addresses = [
                    addr + self.vuln_proj.proj.loader.main_object.min_addr for addr in addresses]
                collect = self.vuln_proj.generate(
                    funcname, addresses, patterns_)
            elif state == "patch":
                addresses = [
                    addr + self.patch_proj.proj.loader.main_object.min_addr for addr in addresses]
                collect = self.patch_proj.generate(
                    funcname, addresses, patterns_)
            else:
                raise NotImplementedError(f"{state} is not considered.")
        except FunctionNotFound:
            return None
        return collect


def getbbs(collect) -> list:
    bbs = []
    for bb in collect.keys():
        constraints = []
        effect = []
        for addr_or_constraint in collect[bb]:
            if addr_or_constraint == "Constraints":
                pass
            else:
                for single_site in collect[bb][addr_or_constraint]:
                    effect.append(single_site)
        bbs.append((bb, constraints, effect))
    return bbs


def extrace_effect(collect) -> list:
    effect = []
    for bb in collect.keys():
        for addr_or_constraint in collect[bb]:
            if addr_or_constraint == "Constraints":
                continue
            for single_site in collect[bb][addr_or_constraint]:
                effect.append(single_site)
    return effect


class Test:
    def __init__(self, sigs: dict[str, list[Signature]]) -> None:
        self.sigs = sigs

    def test_path(self, binary_path: str) -> str:
        project = angr.Project(binary_path)
        simulator = Simulator(project)
        return self.test_project(simulator)

    def test_project(self, simulator: Simulator) -> str:
        # if one think it's vuln, then it is vuln
        exist_patch = False
        results = []
        funcnames = self.sigs.keys()
        # check at least one function is in the binary, else return None
        for funcname in funcnames:
            if simulator.proj.loader.find_symbol(funcname) is not None:
                break
        else:
            logger.critical(f"no function {funcnames} in the signature")
            assert False
        for funcname in self.sigs.keys():
            sigs = self.sigs[funcname]
            result = self.test_func(funcname, simulator, sigs)
            if result == "vuln":
                return "vuln"
            results.append(result)
        print(results)
        for result in results:
            if result == "vuln":
                return "vuln"
            if result == "patch":
                exist_patch = True
        if exist_patch:
            return "patch"
        return "vuln"

    def use_pattern(self, patterns: Patterns) -> str:
        for pattern in patterns.patterns:
            if pattern.pattern == "If":
                return "If"
        for pattern in patterns.patterns:
            if pattern.pattern == "Call":
                return "Call"
        return None

    def _match2len(self, match: list) -> int:
        l = 0
        for m in match:
            if m.ins[0] == "Put":
                l += 1
            elif m.ins[0] == "Store":
                l += 1.5
            elif m.ins[0] == "Condition" or m.ins[0] == "Call":
                l += 2
            else:
                raise NotImplementedError(f"{m.ins[0]} is not considered.")
        return l

    def test_func(self, funcname: str, simulator: Simulator, sigs: list[Signature]) -> str:
        dic = {}
        for sig in sigs:
            dic.update(handle_pattern(sig.patterns))
        try:
            traces: dict = simulator.generate_forall_bb(funcname, dic)
        except FunctionNotFound:
            return None
        result = []
        # test one hunk's signature
        for sig in sigs:
            if sig.state == "vuln":
                vuln_effect, _ = sig.serial()
                patch_effect = []
                vuln_pattern, patch_pattern = sig.patterns, Patterns([])
            elif sig.state == "patch":
                vuln_effect = []
                patch_effect, _ = sig.serial()
                vuln_pattern, patch_pattern = Patterns([]), sig.patterns
            elif sig.state == "modify":
                vuln_info, patch_info = sig.serial()
                vuln_effect, _ = vuln_info
                patch_effect, _ = patch_info
                vuln_pattern, patch_pattern = sig.patterns[0], sig.patterns[1]
            else:
                raise NotImplementedError(f"{sig.state} is not considered.")
            vuln_use_pattern, patch_use_pattern = self.use_pattern(
                vuln_pattern), self.use_pattern(patch_pattern)
            vuln_effect = set(vuln_effect)
            patch_effect = set(patch_effect)
            vuln_effect, patch_effect = vuln_effect-patch_effect, patch_effect-vuln_effect
            if len(vuln_effect) == 0 and len(patch_effect) == 0:
                continue
            logger.info(f"{vuln_effect}, {patch_effect}")
            vuln_match, patch_match = [], []
            all_effects = extrace_effect(traces)
            logger.info(f"{all_effects}")
            test = False
            # essential a add patch
            if len(vuln_effect) == 0:
                for patch in patch_effect:
                    if (patch.ins[0] == "Condition" or patch.ins[0] == "Call") and patch not in all_effects:
                        test = True
                        result.append("vuln")
                        break
            # essential a vuln patch
            if len(patch_effect) == 0:
                for vuln in vuln_effect:
                    if (vuln.ins[0] == "Condition" or vuln.ins[0] == "Call") and vuln not in all_effects:
                        test = True
                        result.append("patch")
                        break
            if test:
                continue
            for vuln in vuln_effect:
                if vuln in all_effects:
                    vuln_match.append(vuln)
            for patch in patch_effect:
                if patch in all_effects:
                    patch_match.append(patch)
            logger.info(f"vuln match {vuln_match}, patch match {patch_match}")
            # If the pattern is If, then we should check there at least one condition in matched effect
            if patch_use_pattern == "If":
                patch_match = [
                    i for i in patch_match if i.ins[0] == "Condition"]
                if len(patch_match) == 0:
                    result.append("vuln")
                    continue
            if vuln_use_pattern == "If":
                vuln_match = [i for i in vuln_match if i.ins[0] == "Condition"]
                if len(vuln_match) == 0:
                    result.append("patch")
                    continue
            vuln_num = self._match2len(vuln_match)
            patch_num = self._match2len(patch_match)
            print(vuln_num, patch_num, funcname)
            if vuln_num == 0 and patch_num == 0:
                continue
            if patch_num == vuln_num:
                continue
            if vuln_num >= patch_num:
                return "vuln"
            result.append("patch" if patch_num > vuln_num else "vuln")
        print(result)
        if len(result) == 0:
            return None
        # if one think it's vuln, then it is vuln
        if "vuln" in result:
            return "vuln"
        if "patch" in result:
            return "patch"
        # if no vuln and patch, then it's vuln
        return "vuln"
