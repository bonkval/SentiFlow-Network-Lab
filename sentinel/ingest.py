import json,shutil,subprocess
from datetime import datetime,timezone
from .models import NetworkEvent

FIELDS=["frame.time_epoch","ip.src","ip.dst","tcp.srcport","udp.srcport","tcp.dstport","udp.dstport","ip.proto","frame.len","dns.qry.name","tcp.flags.reset"]
def tshark_events(interface="1",pcap=""):
    executable=shutil.which("tshark")
    if not executable:raise RuntimeError("TShark was not found. Install Wireshark with TShark and Npcap.")
    command=[executable,*(["-r",pcap] if pcap else ["-l","-i",interface]),"-T","fields"]
    for field in FIELDS:command += ["-e",field]
    command += ["-E","separator=\t","-E","quote=n"]
    process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding="utf-8",errors="replace")
    for line in process.stdout:
        p=line.rstrip("\n").split("\t")+[""]*len(FIELDS)
        try:timestamp=datetime.fromtimestamp(float(p[0]),timezone.utc).isoformat()
        except ValueError:continue
        sport=p[3] or p[4] or "0";dport=p[5] or p[6] or "0"
        yield NetworkEvent(timestamp,p[1] or "unknown",p[2] or "unknown",int(sport.split(",")[0]),int(dport.split(",")[0]),p[7] or "IP",int((p[8] or "0").split(",")[0]),0,"dns" if p[9] else "flow",p[9],"reset" if p[10] and p[10]!="0" else "unknown","pcap" if pcap else "live")

def eve_events(path):
    with open(path,encoding="utf-8") as handle:
        for line in handle:
            row=json.loads(line);flow=row.get("flow",{});dns=row.get("dns",{})
            yield NetworkEvent(row.get("timestamp",datetime.now(timezone.utc).isoformat()),row.get("src_ip","unknown"),row.get("dest_ip","unknown"),int(row.get("src_port",0)),int(row.get("dest_port",0)),row.get("proto","UNKNOWN"),int(flow.get("bytes_toserver",0)),int(flow.get("bytes_toclient",0)),row.get("event_type","flow"),dns.get("rrname",""),"unknown","suricata")
