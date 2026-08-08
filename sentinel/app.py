import json,threading,time
from pathlib import Path
from .detector import Detector
from .ingest import tshark_events
from .simulator import SCENARIOS,generate
from .models import NetworkEvent
from .storage import Storage

class Monitor:
    def __init__(self,db_path="data/sentiflow.db"):
        self.config=json.loads(Path("config.json").read_text(encoding="utf-8"));self.storage=Storage(db_path);self.detector=Detector(self.config,self._incident);self.mode="idle";self.running=False;self.error="";self.started_at=time.time();self.lock=threading.Lock();self.proof={"active":False,"scenario":"","received":0,"total":0,"detected":False,"detection_type":"","stage":"waiting"}
    def _incident(self,incident):
        self.storage.add_incident(incident)
        if self.proof["active"] and incident.scenario_id==self.proof["scenario"]:self.proof.update(detected=True,detection_type=incident.detection_type,stage="detected")
    def process(self,event):
        self.storage.add_event(event);self.detector.process(event)
        if self.proof["active"] and event.scenario_id==self.proof["scenario"]:self.proof["received"]+=1;self.proof["stage"]="detected" if self.proof["detected"] else "analyzing"
    def ingest_external(self,data):
        allowed=set(NetworkEvent.__dataclass_fields__);clean={k:v for k,v in data.items() if k in allowed and k!="id"}
        for required in ("timestamp","source_ip","destination_ip"):
            if required not in clean:raise ValueError(f"Missing required field: {required}")
        clean["source"]="external-test";clean["simulation"]=True
        event=NetworkEvent(**clean);self.process(event);return {"accepted":True,"event_id":event.id,"proof":self.proof}
    def start_proof(self,scenario,total):
        if scenario not in SCENARIOS:raise ValueError("Unknown scenario")
        self.detector.history.clear();self.detector.cooldowns.clear()
        self.proof={"active":True,"scenario":scenario,"name":SCENARIOS[scenario]["name"],"expected":SCENARIOS[scenario]["expected"],"received":0,"total":int(total),"detected":False,"detection_type":"","stage":"receiving"};return self.proof
    def finish_proof(self):self.proof["active"]=False;self.proof["stage"]="complete";return self.proof
    def simulate(self,scenario):
        events=generate(scenario)
        with self.lock:
            self.mode=f"simulation:{scenario}";before=self.storage.stats()["incidents"]
            for event in events:self.process(event)
            after=self.storage.stats()["incidents"];self.mode="idle"
        return {"scenario":scenario,"events":len(events),"new_incidents":after-before,"expected":SCENARIOS[scenario]["expected"]}
    def start_tshark(self,interface="1",pcap=""):
        def worker():
            self.running=True;self.mode="pcap" if pcap else "live";self.error=""
            try:
                for event in tshark_events(interface,pcap):self.process(event)
            except Exception as exc:self.error=str(exc)
            finally:self.running=False;self.mode="idle"
        threading.Thread(target=worker,daemon=True).start()
    def status(self):return {"mode":self.mode,"running":self.running,"error":self.error,"uptime_seconds":int(time.time()-self.started_at),"version":"1.1.0","api_version":2}
