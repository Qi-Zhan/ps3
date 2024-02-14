# PS3

This is a replication package for ICSE'24 paper "PS3: Precise Patch Presence Test based on Semantic Symbolic Signature".

## Requirements

### Environment

- Make sure `addr2line`, `gdb`/ `lldb` exist in your system, we use them to extract information from binary file.
- Our python version is 3.10.

```bash
cd ps3
pip install -r requirements.txt
```

### Binary File

Download the binary file from [here](https://figshare.com/s/3fcd957e10475096569d), unzip and put the binary file to the `binary` directory.
Make sure your derectory structure is the same as below.

```text
.
├── README.md (you are here)
├── dataset
│   ├── CVE_info.jsonl (all CVE information)
│   ├── binary (all binary files, which you should download)
│   │   ├── FFmpeg
│   │   ├── openssl
│   │   ├── libxml2
│   │   └── tcpdump
│   ├── diff (directory for patch files)
│   └── test.jsonl (CVE-binary pair)
└── ps3 (our tool)
```

We provide `openssl`, `libxml2`, `tcpdump` and `FFmpeg` binaries used in our paper. If you want to test other bianries, you can compile the binaies by optimization, compiler, and version followed `dataset/test.jsonl`.

> For a quick start you can only download `libxml2`, `tcpdump`, `openssl` since `FFmpeg` is too large to upload and download. The running process is the same.

## Run

```bash
cd ps3
python main.py
```

Wait for a long time (several hours), and you will get the results in stdout. `ps3/log.txt` contains test results for each CVE-binary pair.

### File Name Format

The target file name format is `filename_vesrsion_optimization_compiler`. For example, `ffmpeg_n4.0_O0_x86_clang` is a binary file generated by clang with `-O0` optimization.

The reference file name format is `cvenumber_commitid_state`. For example, `CVE-2018-0734_8abfe7_vuln` is a vulnerable binary file for the CVE. The `state` can be `vuln` or `patch`, which means the patch file is generated by the commit which fixes the CVE or not.
