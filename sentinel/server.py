import argparse,json,mimetypes
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs,urlparse
from .app import Monitor
from .simulator import SCENARIOS
from .examples import traffic_examples

ROOT=Path(__file__).resolve().parent.parent;MONITOR=Monitor(str(ROOT/"data"/"sentiflow.db"))
class Handler(BaseHTTPRequestHandler):
    def _json(self,data,status=200):
        body=json.dumps(data).encode();self.send_response(status);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(body)));self.send_header("Cache-Control","no-store");self.end_headers();self.wfile.write(body)
    def _body(self):return json.loads(self.rfile.read(int(self.headers.get("Content-Length",0))) or b"{}")
    def do_GET(self):
        parsed=urlparse(self.path);query=parse_qs(parsed.query);limit=int(query.get("limit",[100])[0]);routes={"/api/status":lambda:MONITOR.status(),"/api/stats":lambda:MONITOR.storage.stats(),"/api/incidents":lambda:MONITOR.storage.list_rows("incidents",limit),"/api/events":lambda:MONITOR.storage.list_rows("events",limit),"/api/scenarios":lambda:SCENARIOS,"/api/examples":traffic_examples,"/api/proof":lambda:MONITOR.proof}
        if parsed.path in routes:return self._json(routes[parsed.path]())
        path=ROOT/"web"/("index.html" if parsed.path=="/" else parsed.path.lstrip("/"))
        try:content=path.read_bytes()
        except (FileNotFoundError,IsADirectoryError):return self._json({"error":"Not found"},404)
        self.send_response(200);self.send_header("Content-Type",mimetypes.guess_type(path)[0] or "application/octet-stream");self.send_header("Content-Length",str(len(content)));self.send_header("Cache-Control","no-store");self.end_headers();self.wfile.write(content)
    def do_POST(self):
        try:
            if self.path=="/api/simulate":return self._json(MONITOR.simulate(self._body().get("scenario","benign")))
            if self.path=="/api/events":return self._json(MONITOR.ingest_external(self._body()),202)
            if self.path=="/api/proof/start":
                body=self._body();return self._json(MONITOR.start_proof(body.get("scenario","benign"),body.get("total",0)))
            if self.path=="/api/proof/finish":return self._json(MONITOR.finish_proof())
            if self.path=="/api/reset":MONITOR.storage.clear();MONITOR.detector.history.clear();MONITOR.detector.cooldowns.clear();return self._json({"ok":True})
            if self.path.startswith("/api/incidents/"):
                incident_id=self.path.split("/")[3];status=self._body().get("status","closed")
                if status not in {"open","investigating","closed"}:return self._json({"error":"Invalid status"},400)
                return self._json({"ok":MONITOR.storage.update_status(incident_id,status)})
            return self._json({"error":"Not found"},404)
        except (ValueError,KeyError,json.JSONDecodeError) as exc:return self._json({"error":str(exc)},400)
    def log_message(self,fmt,*args):pass
def main():
    parser=argparse.ArgumentParser(description="SentiFlow local IDS");parser.add_argument("--host",default="127.0.0.1");parser.add_argument("--port",type=int,default=8000);parser.add_argument("--source",choices=["idle","live","pcap"],default="idle");parser.add_argument("--interface",default="1");parser.add_argument("--pcap",default="");args=parser.parse_args()
    if args.source=="live":MONITOR.start_tshark(args.interface)
    elif args.source=="pcap":
        if not args.pcap:parser.error("--pcap is required for pcap source")
        MONITOR.start_tshark(pcap=args.pcap)
    server=ThreadingHTTPServer((args.host,args.port),Handler);print(f"SentiFlow is running at http://{args.host}:{args.port}");print("Press Ctrl+C to stop. All data stays on this computer.")
    try:server.serve_forever()
    except KeyboardInterrupt:print("\nStopping SentiFlow.")
    finally:server.server_close()
if __name__=="__main__":main()
