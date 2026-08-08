import json,unittest
from pathlib import Path
from sentinel.detector import Detector
from sentinel.simulator import SCENARIOS,generate
class DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.config=json.loads(Path("config.json").read_text())
    def run_scenario(self,name):
        found=[];detector=Detector(self.config,found.append)
        for event in generate(name):detector.process(event)
        return {x.detection_type for x in found}
    def test_attack_scenarios(self):
        for name,meta in SCENARIOS.items():
            if meta["expected"]!="BENIGN":
                with self.subTest(name=name):self.assertIn(meta["expected"],self.run_scenario(name))
    def test_benign_does_not_alert(self):self.assertEqual(set(),self.run_scenario("benign"))
if __name__=="__main__":unittest.main()
