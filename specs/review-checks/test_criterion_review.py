import importlib.util,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location("gate",Path(__file__).with_name("check_criterion_review.py"))
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
class Cases(unittest.TestCase):
    def setUp(self):self.d,self.b,self.o,self.c,self.t,self.a=gate.inputs()
    def run_gate(self):return gate.validate(self.d,self.b,self.o,self.c,self.t,self.a)
    def test_valid(self):self.assertEqual(self.run_gate(),[])
    def test_lost(self):self.d["rows"].pop();self.assertTrue(self.run_gate())
    def test_native_link_drift(self):self.d["rows"][0]["task_ids"]=[];self.assertTrue(self.run_gate())
    def test_missing_test(self):self.a.discard(self.d["rows"][0]["test_candidates"][0]);self.assertTrue(self.run_gate())
    def test_source_drift(self):self.c[next(iter(self.c))]+=b"\n";self.assertTrue(self.run_gate())
    def test_missing_task(self):self.t=self.t.replace(self.d["rows"][0]["review_task_id"],"LOST");self.assertTrue(self.run_gate())
    def test_fake_completion(self):
        r=self.d["rows"][0];r["state"]="verified";self.t=self.t.replace("[ ] "+r["review_task_id"],"[x] "+r["review_task_id"]);self.assertTrue(self.run_gate())
    def test_authority(self):self.d["public_release_authorized"]=True;self.assertTrue(self.run_gate())
