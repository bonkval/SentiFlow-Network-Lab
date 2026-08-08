import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sentinel.detector import Detector
from sentinel.simulator import SCENARIOS,generate
config=json.loads(Path("config.json").read_text());tp=fp=fn=tn=0
print("SentiFlow deterministic validation\n")
for name,meta in SCENARIOS.items():
    found=[];detector=Detector(config,found.append)
    for event in generate(name):detector.process(event)
    types={x.detection_type for x in found};expected=meta["expected"]
    if expected=="BENIGN":ok=not types;tn+=int(ok);fp+=int(not ok)
    else:ok=expected in types;tp+=int(ok);fn+=int(not ok)
    print(f"{'PASS' if ok else 'FAIL':4}  {name:14} expected={expected:22} observed={','.join(sorted(types)) or 'BENIGN'}")
precision=tp/(tp+fp) if tp+fp else 0;recall=tp/(tp+fn) if tp+fn else 0
print(f"\nTP={tp} FP={fp} TN={tn} FN={fn}");print(f"Precision={precision:.3f} Recall={recall:.3f}")
