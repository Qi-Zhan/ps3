from dataclasses import dataclass
import jsonlines
from settings import TEST_FILE

@dataclass
class TestJson:
    file: str
    cve: str
    commit: str
    ground_truth: str
    project: str

@dataclass
class TestResult:
    test_json: TestJson
    result: str

class Dataset:
    def __init__(self, tests: list[TestJson]) -> None:
        self.tests = tests
        self.rearrange()

    @classmethod
    def from_file(cls):
        # read list of Test json from jsonlines
        test = []
        with jsonlines.open(f"{TEST_FILE}", 'r') as f:
            for line in f:
                test.append(TestJson(**line))
        return cls(test)
    
    def rearrange(self):
        test_different_cve = {}
        for test in self.tests:
            if test.cve not in test_different_cve:
                test_different_cve[test.cve] = []
            test_different_cve[test.cve].append(test)
        self.tests = test_different_cve

class Evaluator:

    def precision(self, results: list[TestResult]) -> float:
        rr = 0
        ri = 0
        for test_result in results:
            if test_result.result == 'vuln' and test_result.test_json.ground_truth == 'vuln':
                rr += 1
            if test_result.result == 'vuln' and test_result.test_json.ground_truth == 'patch':
                ri += 1
        if rr + ri == 0:
            return 1
        return rr / (rr + ri)

    def recall(self, results: list[TestResult]) -> float:
        count = 0
        for test_result in results:
            if test_result.test_json.ground_truth == 'vuln':
                count += 1
        correct = 0
        for test_result in results:
            if test_result.result == 'vuln' and test_result.test_json.ground_truth == 'vuln':
                correct += 1
        if count == 0 and correct == 0:
            return 1
        return correct / count
    
    def f1(self, results: list[TestResult]) -> float:
        p = self.precision(results)
        r = self.recall(results)
        if p == 0 and r == 0:
            return 0
        return 2 * p * r / (p + r)
    
    def precision_recall_f1(self, results: list[TestResult]) -> tuple[float, float, float]:
        return self.precision(results), self.recall(results), self.f1(results)
    
    # parse to get compiler and optimization
    # for example libcrypto.so_openssl-3.0.4_O1_x86_gcc -> (O1, gcc)
    def _parse(self, name: str) -> tuple[str, str]:
        name = name.split('_')
        return name[-3], name[-1]
    
    def evaulate_RQ2(self, test_results: list[TestResult]) -> dict:
        group = {(opt, compiler): [] for opt in ['O0', 'O1', 'O2', 'O3'] for compiler in ['gcc', 'clang']}
        for test in test_results:
            opt, compiler = self._parse(test.test_json.file)
            group[(opt, compiler)].append(test)
        # calculate precision, recall, f1 for each group
        result = {}
        for key, value in group.items():
            result[key] = self.precision_recall_f1(value)
        return result
