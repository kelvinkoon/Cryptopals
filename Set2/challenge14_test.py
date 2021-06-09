from Set2.challenge14 import *

def test_breakOracleByteAtATimeHarder():
    ecb_oracle = HarderECBOracle()
    result_bytes = breakOracleByteAtATimeHarder(ecb_oracle) 
    assert False
