import os
ROOT_PATH = os.path.abspath('../') # project root path
DATASET_PATH = os.path.join(ROOT_PATH, 'dataset') # dataset path
BINARY_PATH = os.path.join(DATASET_PATH, 'binary')
DIFF_PATH= os.path.join(DATASET_PATH, 'diff')
TEST_FILE= os.path.join(DATASET_PATH, 'test.jsonl')
ADDR2LINE = 'addr2line'

REPO_PATH = "../dataset/repos"