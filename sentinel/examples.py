from .simulator import SCENARIOS,generate

ORDER=["port_scan","host_scan","brute_force","beaconing","exfiltration","dns_tunnel","indicator","benign"]
DETAILS={
"port_scan":("Reconnaissance","20 unique ports / 60 seconds","high"),
"host_scan":("Discovery","15 unique hosts / 60 seconds","high"),
"brute_force":("Credential access","12 rejected attempts / 60 seconds","high"),
"beaconing":("Command and control","6 regular callbacks","medium"),
"exfiltration":("Exfiltration","50 MB outbound / 120 seconds","critical"),
"dns_tunnel":("Command and control","Long DNS label or query","medium"),
"indicator":("Threat intelligence","Local denylist match","critical"),
"benign":("Baseline","No threshold crossed","none")}

def traffic_examples():
    output=[]
    for key in ORDER:
        meta=SCENARIOS[key];events=generate(key);category,threshold,severity=DETAILS[key]
        output.append({"id":key,"name":meta["name"],"description":meta["description"],"category":category,"threshold":threshold,"severity":severity,"expected":meta["expected"],"events":[event.to_dict() for event in events]})
    return output
