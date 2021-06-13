from Set2.challenge14 import *
from shared.validation_functions import *

NUM_ITERATIONS = 50
EXPECTED_HASH_HEX_STR = "0f7a938a0a6fc97f763710454b139317f4db7ed2"


def test_breakOracleByteAtATimeHarder():
    for i in range(NUM_ITERATIONS):
        ecb_oracle = HarderECBOracle()
        result_bytes = breakOracleByteAtATimeHarder(ecb_oracle)
        assert hashBytesToSHA1Str(result_bytes) == EXPECTED_HASH_HEX_STR
