# This file is responsible for parser debug info extracted by gdb or lldb.
import logging
import subprocess
import os
from settings import ADDR2LINE

VULN = 0
PATCH = 1
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class DebugParser:
    def __init__(self, debug_infos: list[list[str]], binary_path: str = None):
        self.parse_result = {}
        self.binary_path = binary_path
        self.debug_infos = debug_infos
        for debug_info in debug_infos:
            debug_info = [line.strip() for line in debug_info]
            # union all debug info
            self.parse_result.update(self._debug_parse(debug_info))

    def _debug_parse(self, debug_info: list[str]) -> dict:
        dic = {}
        addr = []
        i = 0
        funcname = None
        if os.uname().sysname == 'Linux':
            while i < len(debug_info):
                line = debug_info[i]
                if line.startswith('Dump of assembler code for function'):
                    funcname = line.split()[-1]
                    funcname = funcname[:funcname.find(':')]
                    i += 1
                    continue
                if line.startswith('warning: Source file is more recent than executable.'):
                    logger.info('Source file is more recent than executable.')
                    i += 1
                    continue
                if line.startswith('End of assembler dump.'):
                    i += 1
                    continue
                tokens = line.strip().split()
                if len(tokens) != 0:
                    addr.append(int(tokens[0], 16))
                i += 1
            dic = self._addr_from_lines(addr)
            assert funcname is not None
            dic = {funcname: dic}
            return dic
        elif os.uname().sysname == 'Darwin':
            # print(debug_info)
            # input()
            for line in debug_info:
                if line.startswith('(lldb)'):
                    if line.startswith('(lldb) disassemble -n'):
                        funcname = line.split()[-1]
                # E.g. libcrypto.so_openssl-1.1.1_O0_x86_gcc[0x1270d3] <+1026>: callq  0xd80cd                   ; BN_clear_free
                else:
                    tokens = line.strip().split()
                    if len(tokens) != 0:
                        s = tokens[0]
                        s = s[s.find('[')+1:s.find(']')]
                        try:
                            addr.append(int(s, 16))
                        except ValueError:
                            continue
            assert funcname is not None
            dic = self._addr_from_lines(addr)
            dic = {funcname: dic}
            return dic
        else:
            raise NotImplementedError(
                f'Unsupported OS {os.uname().sysname} !!!')

    def _addr_from_lines(self, addr_list):
        assert self.binary_path is not None
        dic = {}
        addr_list = [hex(addr) for addr in addr_list]
        p = subprocess.Popen([ADDR2LINE, '-afip', '-e', self.binary_path],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        addr_str = '\n'.join(addr_list)
        output, errors = p.communicate(input=addr_str.encode('utf-8'))
        if errors:
            print('Error:', errors.decode('utf-8'))
        else:
            for line in output.decode('utf-8').splitlines():
                l = line.strip()
                if l.startswith('0x'):
                    # E.g.
                    # 0xffffffc000a7aa9c: wcdcal_hwdep_ioctl_shared at /home/hang/pm/src-angler-20160801/sound/soc/codecs/wcdcal-hwdep.c:59
                    # 0xffffffc000a7ab18: wcdcal_hwdep_ioctl_shared at /home/hang/pm/src-angler-20160801/sound/soc/codecs/wcdcal-hwdep.c:77 (discriminator 1)
                    tokens = l.split(':')
                    addr = int(tokens[0], 16)
                    func = tokens[1].split(' ')[1]
                    lno = int(tokens[2].split(' ')[0])
                    if lno in dic:
                        dic[lno].append(addr)
                    else:
                        dic[lno] = [addr]
                elif 'inlined by' in l:
                    # E.g.
                    # (inlined by) wcdcal_hwdep_ioctl_shared at /home/hang/pm/src-angler-20160801/sound/soc/codecs/wcdcal-hwdep.c:66
                    tokens = l.split(':')
                    lno = int(tokens[1].split(' ')[0])
                    func = tokens[0].split(' ')[3]
                    if lno in dic:
                        dic[lno].append(addr)
                    else:
                        dic[lno] = [addr]
                else:
                    logger.warn(f'Unrecognized ADDR2LINE output {l} !!!')
                    continue
        return dic

    @classmethod
    def from_binary(cls, binary_path: str, funcnames: list[str]):
        debug_infos = []
        for func_name in funcnames:
            if os.uname().sysname == 'Linux':
                cmd = f'gdb -batch -ex "file {binary_path}" -ex "disassemble {func_name}"'
            elif os.uname().sysname == 'Darwin':
                cmd = f'lldb -b -o "disassemble -n {func_name}" -o quit {binary_path}'
            else:
                raise NotImplementedError(
                    f'Unsupported OS {os.uname().sysname} !!!')
            try:
                info = subprocess.check_output(
                    cmd, shell=True).decode('utf-8').splitlines()
            except subprocess.CalledProcessError:
                logger.error(f'Failed to execute {cmd} !!!')
                continue
            debug_infos.append(info)
        return cls(debug_infos, binary_path)

    def exists(self, funcname: str, src_line_number: int) -> bool:
        return funcname in self.parse_result and src_line_number in self.parse_result[funcname]

    def line2addr(self, funcname: str, src_line_number: int) -> list[int]:
        if self.exists(funcname, src_line_number):
            return self.parse_result[funcname][src_line_number]
        else:
            return []

    def __str__(self) -> str:
        return str(self.parse_result)


class DebugParser2:
    def __init__(self, vuln_parser: DebugParser, patch_parser: DebugParser):
        self.vuln_parser = vuln_parser
        self.patch_parser = patch_parser

    @classmethod
    def from_files(cls, vuln_diff: str, patch_diff: str):
        return cls(DebugParser.from_file(vuln_diff), DebugParser.from_file(patch_diff))

    @classmethod
    def from_binary(cls, vuln_binary_path: str, patch_binary_path: str, funcnames: list[str]):
        return cls(DebugParser.from_binary(vuln_binary_path, funcnames), DebugParser.from_binary(patch_binary_path, funcnames))
