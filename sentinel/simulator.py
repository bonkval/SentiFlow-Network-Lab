from datetime import datetime,timedelta,timezone
from .models import NetworkEvent

SCENARIOS={
"port_scan":{"name":"Port scan","expected":"PORT_SCAN","description":"One test host touches 30 ports."},"host_scan":{"name":"Host discovery","expected":"HOST_SCAN","description":"One test host touches 20 private hosts."},"brute_force":{"name":"Brute force","expected":"BRUTE_FORCE","description":"Repeated rejected SSH connections."},"beaconing":{"name":"C2 beaconing","expected":"BEACONING","description":"Regular callback metadata every 30 seconds."},"exfiltration":{"name":"Data exfiltration","expected":"POSSIBLE_EXFILTRATION","description":"Large dummy outbound byte counts."},"dns_tunnel":{"name":"DNS tunnelling","expected":"DNS_ANOMALY","description":"Long synthetic DNS labels."},"indicator":{"name":"Indicator match","expected":"INDICATOR_MATCH","description":"Connection to documentation-only test IP."},"benign":{"name":"Normal browsing","expected":"BENIGN","description":"Ordinary mixed web and DNS metadata."}}

def generate(name):
    if name not in SCENARIOS:raise ValueError("Unknown scenario")
    base=datetime.now(timezone.utc)-timedelta(minutes=5)
    def event(i=0,**kw):
        values=dict(timestamp=(base+timedelta(seconds=i)).isoformat(),source_ip="192.168.1.50",destination_ip="192.168.1.10",source_port=51000+i,destination_port=443,protocol="TCP",bytes_sent=500,bytes_received=1000,source="simulation",simulation=True,scenario_id=name,label=SCENARIOS[name]["expected"]);values.update(kw);return NetworkEvent(**values)
    if name=="port_scan":return[event(i,destination_port=20+i,outcome="reset") for i in range(30)]
    if name=="host_scan":return[event(i,destination_ip=f"192.168.2.{i+1}",destination_port=445,outcome="reset") for i in range(20)]
    if name=="brute_force":return[event(i*3,destination_port=22,outcome="failed") for i in range(16)]
    if name=="beaconing":return[event(i*30,destination_ip="198.51.100.80",destination_port=443) for i in range(8)]
    if name=="exfiltration":return[event(i*10,destination_ip="198.51.100.80",bytes_sent=12000000,bytes_received=200) for i in range(6)]
    if name=="dns_tunnel":return[event(0,protocol="UDP",destination_port=53,event_type="dns",dns_query="dGhpcy1pcy1oYXJtbGVzcy1zeW50aGV0aWMtZGF0YS1vbmx5.example.test")]
    if name=="indicator":return[event(0,destination_ip="203.0.113.66")]
    normal_intervals=[0,3,11,18,37,41,72,95]
    return[event(i,destination_ip="93.184.216.34",destination_port=443,outcome="success",label="BENIGN") for i in normal_intervals]
