from collections import defaultdict,deque
from datetime import datetime
from ipaddress import ip_address,ip_network
from statistics import mean
from .models import Incident

def epoch(value): return datetime.fromisoformat(value.replace("Z","+00:00")).timestamp()

class Detector:
    def __init__(self,config,emit): self.config=config; self.emit=emit; self.history=defaultdict(deque); self.cooldowns={}; self.home=[ip_network(x) for x in config["home_networks"]]
    def _internal(self,ip):
        try:return any(ip_address(ip) in n for n in self.home)
        except ValueError:return False
    def _window(self,key,event,seconds):
        q=self.history[key]; q.append(event); cutoff=epoch(event.timestamp)-seconds
        while q and epoch(q[0].timestamp)<cutoff:q.popleft()
        return list(q)
    def _alert(self,event,dtype,severity,title,description,evidence,events,cooldown=45):
        key=(dtype,event.source_ip,event.destination_ip); now=epoch(event.timestamp)
        if now-self.cooldowns.get(key,0)<cooldown:return
        self.cooldowns[key]=now; self.emit(Incident(dtype,severity,title,description,event.source_ip,event.destination_ip,evidence,events[0].timestamp,events[-1].timestamp,event.source,event.simulation,event.scenario_id))
    def process(self,event):
        self._scan(event); self._brute(event); self._beacon(event); self._exfil(event); self._dns(event); self._indicator(event)
    def _scan(self,e):
        r=self.config["port_scan"]; xs=self._window(("port",e.source_ip,e.destination_ip),e,r["window_seconds"]); ports={x.destination_port for x in xs if x.destination_port}
        if len(ports)>=r["unique_ports"]: self._alert(e,"PORT_SCAN","high","Possible port scan",f"{e.source_ip} contacted many ports on one host.",{"unique_ports":len(ports),"threshold":r["unique_ports"],"window_seconds":r["window_seconds"],"sample_ports":sorted(ports)[:20]},xs)
        r=self.config["host_scan"]; xs=self._window(("host",e.source_ip),e,r["window_seconds"]); hosts={x.destination_ip for x in xs}
        if len(hosts)>=r["unique_hosts"]: self._alert(e,"HOST_SCAN","high","Possible host discovery",f"{e.source_ip} contacted many destination hosts.",{"unique_hosts":len(hosts),"threshold":r["unique_hosts"],"window_seconds":r["window_seconds"]},xs)
    def _brute(self,e):
        r=self.config["brute_force"]
        if e.destination_port not in r["ports"] or e.outcome not in {"failed","rejected","reset"}:return
        xs=self._window(("brute",e.source_ip,e.destination_ip,e.destination_port),e,r["window_seconds"])
        if len(xs)>=r["attempts"]: self._alert(e,"BRUTE_FORCE","high","Repeated authentication attempts",f"Repeated failed connections to port {e.destination_port}.",{"attempts":len(xs),"threshold":r["attempts"],"port":e.destination_port,"window_seconds":r["window_seconds"]},xs)
    def _beacon(self,e):
        r=self.config["beaconing"]; xs=self._window(("beacon",e.source_ip,e.destination_ip,e.destination_port),e,r["window_seconds"])
        if len(xs)<r["minimum_events"]:return
        if self._internal(e.destination_ip) or any(x.bytes_sent>r["maximum_bytes_per_event"] for x in xs):return
        times=[epoch(x.timestamp) for x in xs]; intervals=[b-a for a,b in zip(times,times[1:])]; avg=mean(intervals)
        if avg<2:return
        jitter=max(abs(x-avg) for x in intervals)/avg
        if jitter<=r["max_interval_jitter_ratio"]: self._alert(e,"BEACONING","medium","Periodic outbound beaconing","Connections repeat at a highly regular interval.",{"events":len(xs),"average_interval_seconds":round(avg,2),"jitter_ratio":round(jitter,3),"maximum_jitter_ratio":r["max_interval_jitter_ratio"]},xs,300)
    def _exfil(self,e):
        r=self.config["exfiltration"]
        if not self._internal(e.source_ip) or self._internal(e.destination_ip):return
        xs=self._window(("exfil",e.source_ip,e.destination_ip),e,r["window_seconds"]); total=sum(x.bytes_sent for x in xs)
        if total>=r["outbound_bytes"]: self._alert(e,"POSSIBLE_EXFILTRATION","critical","Large outbound data transfer","Outbound byte volume exceeded the configured threshold.",{"outbound_bytes":total,"threshold_bytes":r["outbound_bytes"],"window_seconds":r["window_seconds"]},xs,120)
    def _dns(self,e):
        if not e.dns_query:return
        r=self.config["dns"]; longest=max(map(len,e.dns_query.split(".")))
        if len(e.dns_query)>r["maximum_query_length"] or longest>r["maximum_label_length"]: self._alert(e,"DNS_ANOMALY","medium","Suspicious DNS query shape","A DNS name is unusually long and may encode data.",{"query":e.dns_query,"query_length":len(e.dns_query),"longest_label":longest},[e],60)
    def _indicator(self,e):
        matched=e.destination_ip if e.destination_ip in self.config["denylisted_ips"] else e.source_ip if e.source_ip in self.config["denylisted_ips"] else ""
        if matched:self._alert(e,"INDICATOR_MATCH","critical","Known suspicious indicator",f"Traffic involved configured indicator {matched}.",{"matched_ip":matched,"list":"local denylist"},[e],300)
