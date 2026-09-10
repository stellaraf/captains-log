#!/usr/bin/env python3
"""Bounded synthetic ClickHouse scale benchmark; never writes the live events table.

Uses server-side numbers()/INSERT SELECT, so this is NOT a Syslog throughput test.
Credentials are read from the private local env file and are never printed.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[1]
TABLE="nebulalog.benchmark_events"
MARKER="NebulaLog synthetic benchmark schema 1; no real firewall data"
GIB=1024**3

class StopBenchmark(RuntimeError):pass


def secure_env(path):
    info=path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_mode & 0o077:
        raise StopBenchmark("Credential env file must be a private regular file")
    result={}
    for line in path.read_text().splitlines():
        if line and not line.startswith("#"):
            key,value=line.split("=",1);result[key]=value
    return result


class ClickHouse:
    def __init__(self,env_file,endpoint):
        parsed=urllib.parse.urlparse(endpoint)
        if parsed.hostname not in ("127.0.0.1","localhost","::1") or parsed.scheme!="http":
            raise StopBenchmark("Benchmark only permits the explicitly local development ClickHouse")
        self.endpoint=endpoint
        values=secure_env(env_file)
        self.authorization="Basic "+base64.b64encode(("nebulalog:"+values["CH_PASSWORD"]).encode()).decode()
        self.run_id="nebulalog-benchmark-"+uuid.uuid4().hex
        self.counter=0
    def execute(self,sql,params=None,timeout=180,overrides=None):
        self.counter+=1
        settings={"max_threads":"2","max_memory_usage":str(512*1024**2),"max_execution_time":"120",
                  "max_insert_threads":"1","max_block_size":"8192","max_insert_block_size":"8192","min_insert_block_size_rows":"0",
                  "min_insert_block_size_bytes":str(16*1024**2),"wait_end_of_query":"1",
                  "date_time_output_format":"iso","query_id":self.run_id+"-"+str(self.counter)}
        settings.update(overrides or {})
        for key,value in (params or {}).items():settings["param_"+key]=str(value)
        request=urllib.request.Request(self.endpoint+"?"+urllib.parse.urlencode(settings),data=sql.encode(),method="POST",
                                       headers={"Authorization":self.authorization,"Content-Type":"text/plain"})
        try:
            with urllib.request.urlopen(request,timeout=timeout) as response:
                data=response.read(16*1024**2)
                if response.headers.get("X-ClickHouse-Exception-Code"):
                    raise StopBenchmark("ClickHouse rejected benchmark query (details omitted to protect credentials)")
                if len(data)>=16*1024**2:raise StopBenchmark("Unexpected oversized benchmark response")
                return data
        except urllib.error.HTTPError as exc:
            code=exc.headers.get("X-ClickHouse-Exception-Code", "unknown")
            raise StopBenchmark(f"ClickHouse rejected benchmark query (HTTP {exc.code}, exception {code}; credentials omitted)") from None
        except (urllib.error.URLError,TimeoutError):
            raise StopBenchmark("ClickHouse benchmark request failed (credentials and server details omitted)") from None
    def rows(self,sql,params=None):
        return [json.loads(line) for line in self.execute(sql+" FORMAT JSONEachRow",params).splitlines() if line]


def table_state(ch):
    part=ch.rows("SELECT count() AS parts,sum(bytes_on_disk) AS bytes,sumIf(rows,active) AS rows,sumIf(bytes_on_disk,active) AS active_bytes,sumIf(data_uncompressed_bytes,active) AS uncompressed_bytes,sumIf(marks_bytes,active) AS marks_bytes FROM system.parts WHERE database='nebulalog' AND table='benchmark_events'")[0]
    part={key:int(value or 0) for key,value in part.items()}
    disk=ch.rows("SELECT total_space,free_space FROM system.disks WHERE name='default'")[0]
    auxiliary=ch.rows("SELECT sum(bytes_on_disk) AS bytes FROM system.parts WHERE database='nebulalog' AND table='benchmark_retention'")[0]
    part["retention_test_bytes"]=int(auxiliary["bytes"] or 0)
    part["bytes"]+=part["retention_test_bytes"]
    part["database_free_bytes"]=int(disk["free_space"])
    part["host_free_bytes"]=shutil.disk_usage(ROOT).free
    return part


def safety(ch,budget,host_min,*,projected_batch_bytes=0):
    state=table_state(ch)
    if state["host_free_bytes"]<host_min:raise StopBenchmark("Host physical free space fell below the required reserve")
    if state["database_free_bytes"]<10*GIB:raise StopBenchmark("ClickHouse filesystem free space is below 10 GiB")
    if state["bytes"]+projected_batch_bytes>budget:raise StopBenchmark("Benchmark would exceed the isolated-table data budget")
    return state


def dataset_sql(days):
    # 130-field TRAFFIC CSV layout derived from the canonical core; extensions
    # are intentionally blank. This is clearly marked synthetic, not parsed live.
    fields=["''"]*130
    expressions={0:"'1'",1:"wire_time",2:"'BENCHMARK'",3:"'TRAFFIC'",4:"'end'",5:"'1'",6:"wire_time",
      7:"source_ip",8:"destination_ip",9:"'192.0.2.10'",10:"destination_ip",11:"rule_name",12:"source_user",13:"''",
      14:"application",15:"'vsys1'",16:"'trust'",17:"'untrust'",18:"'ethernet1/1'",19:"'ethernet1/2'",
      20:"'NebulaLog-Benchmark'",21:"'0'",22:"toString(n % 1000000)",23:"'1'",24:"toString(source_port)",25:"toString(destination_port)",
      26:"toString(source_port)",27:"toString(destination_port)",28:"'0x400000'",29:"'tcp'",30:"policy_action",31:"toString(total_bytes)",
      32:"toString(sent_bytes)",33:"toString(total_bytes-sent_bytes)",34:"toString(packet_count)",35:"wire_time",36:"toString(n%3600)",
      37:"'any'",38:"'0'",39:"toString(n)",40:"'0x0'",41:"'10.0.0.0-10.255.255.255'",42:"'US'",43:"'0'",
      44:"toString(intDiv(packet_count,2))",45:"toString(packet_count-intDiv(packet_count,2))",46:"'tcp-fin'",
      47:"'0'",48:"'0'",49:"'0'",50:"'0'",51:"'vsys1'",52:"'BENCHMARK'",65:"'11111111-1111-4111-8111-111111111111'",
      102:"formatDateTime(event_at,'%Y-%m-%dT%H:%i:%S.000000Z')"}
    for position,value in expressions.items():fields[position]=value
    csv_array="["+",".join(fields)+"]"
    definitions=f"""WITH number+{{offset:UInt64}} AS n,
    toDateTime64({{anchor:String}},6,'UTC')-toIntervalSecond((intDiv(n,{{rows_per_day:UInt64}})%{days})*86400+n%86400) AS event_at,
    formatDateTime(event_at,'%Y/%m/%d %H:%i:%S') AS wire_time,
    concat('10.20.',toString(intDiv(n%65536,256)),'.',toString(n%256)) AS source_ip,
    concat('198.51.100.',toString(n%254+1)) AS destination_ip,
    arrayElement(['ssl','web-browsing','dns','quic','ms-rdp','ssh','smtp','office365-base','google-base','ntp','snmp','ping'],n%12+1) AS application,
    arrayElement([443,80,53,443,3389,22,25,443,443,123,161,0],n%12+1) AS destination_port,
    toUInt16(1024+n%64512) AS source_port,
    if(n%20=0,'deny',if(n%50=0,'drop','allow')) AS policy_action,
    concat('Benchmark policy ',toString(n%64)) AS rule_name,
    concat('benchmark/user',toString(n%128)) AS source_user,
    toUInt64(512+(n%65536)*32) AS total_bytes,
    intDiv(total_bytes,3) AS sent_bytes,
    toUInt64(4+n%1024) AS packet_count,
    {csv_array} AS csv_fields,
    concat('<14>',formatDateTime(event_at,'%b %e %T'),' BENCHMARK ',arrayStringConcat(csv_fields,',')) AS raw_message"""
    columns={
     "id":"concat('00000000-0000-4000-8000-',leftPad(toString(n),12,'0'))",
     "ingested_at":"event_at","received_at":"event_at","generated_at":"event_at","expires_at":"toDateTime({anchor:String},'UTC')+INTERVAL 365 DAY",
     "sender_ip":"'192.0.2.10'","serial":"'BENCHMARK'","device_name":"'BENCHMARK'","vsys":"'vsys1'",
     "log_type":"'traffic'","wire_type":"'TRAFFIC'","subtype":"'end'","schema_version":"'synthetic-reference-2026-09-07'",
     "schema_id":"'benchmark-traffic-130'","panos_version":"''","timestamp_timezone":"'UTC'","parser_version":"'native-sql-benchmark-no-parser'",
     "parse_status":"'synthetic'","parse_error":"''","raw":"raw_message","raw_base64":"base64Encode(raw_message)",
     "fields":"toJSONString(csv_fields)","extra_fields":"'{}'","src_ip":"source_ip","dst_ip":"destination_ip","src_port":"source_port","dst_port":"destination_port",
     "src_zone":"'trust'","dst_zone":"'untrust'","src_user":"source_user","dst_user":"''","app":"application","previous_app":"'incomplete'",
     "action":"policy_action","rule":"rule_name","session_end_reason":"'tcp-fin'","bytes":"total_bytes","bytes_sent":"sent_bytes",
     "bytes_received":"total_bytes-sent_bytes","packets":"packet_count","session_id":"toString(n%1000000)","nat_src_ip":"'192.0.2.10'","nat_dst_ip":"destination_ip",
     "severity":"''","description":"'Synthetic reserved-address benchmark; no customer records'"}
    return "INSERT INTO "+TABLE+" ("+",".join(columns)+") "+definitions+" SELECT "+",".join(columns.values())+" FROM numbers({batch:UInt64})"



def wait_for_headroom(ch,budget,host_min):
    deadline=time.monotonic()+120
    announced=False
    while True:
        safety(ch,budget,host_min)
        resident=ch.rows("SELECT value FROM system.asynchronous_metrics WHERE metric='MemoryResident'")
        memory=float(resident[0]["value"]) if resident else 0
        merges=ch.rows("SELECT count() AS count,sum(memory_usage) AS memory FROM system.merges WHERE database='nebulalog' AND table='benchmark_events'")[0]
        if memory<1.8*GIB and int(merges["memory"] or 0)<384*1024**2:return
        if not announced:
            print(json.dumps({"stage":"waiting_for_shared_memory_headroom","rss_bytes":int(memory),"active_benchmark_merges":int(merges["count"])}),flush=True)
            announced=True
        if time.monotonic()>deadline:raise StopBenchmark("Shared ClickHouse memory pressure did not subside; stopped to preserve live collection")
        time.sleep(2)


def retention_test(ch,budget,host_min):
    safety(ch,budget,host_min)
    name="nebulalog.benchmark_retention"
    existing=ch.rows("SELECT comment FROM system.tables WHERE database='nebulalog' AND name='benchmark_retention'")
    if existing:raise StopBenchmark("Retention test table already exists; review before rerunning")
    ch.execute("CREATE TABLE "+name+" AS "+TABLE)
    ch.execute("ALTER TABLE "+name+" MODIFY COMMENT 'NebulaLog synthetic retention test; no real firewall data'")
    ch.execute("INSERT INTO "+name+" SELECT * REPLACE (now()+INTERVAL 1 DAY AS expires_at) FROM "+TABLE+" LIMIT 10000")
    before=int(ch.rows("SELECT count() AS rows FROM "+name)[0]["rows"])
    begin=time.perf_counter()
    ch.execute("ALTER TABLE "+name+" MODIFY TTL expires_at - INTERVAL 2 DAY DELETE",overrides={"mutations_sync":"2"})
    ch.execute("ALTER TABLE "+name+" MATERIALIZE TTL",overrides={"mutations_sync":"2"})
    after=int(ch.rows("SELECT count() AS rows FROM "+name)[0]["rows"])
    seconds=time.perf_counter()-begin
    if before!=10000 or after!=0:raise StopBenchmark("Isolated TTL materialization did not delete expected synthetic rows")
    ch.execute("DROP TABLE "+name+" SYNC")
    safety(ch,budget,host_min)
    return {"rows_before":before,"rows_after":after,"seconds":seconds,"operation":"isolated synthetic table TTL materialization; table dropped after empty verification"}


def csv_export(ch,output_dir,budget,host_min):
    # Temporary external-sort files also consume the benchmark's disk allowance.
    safety(ch,budget,host_min,projected_batch_bytes=GIB)
    sql="SELECT received_at,serial,src_ip,dst_ip,app,action,rule FROM "+TABLE+" WHERE log_type='traffic' ORDER BY received_at DESC,id DESC LIMIT 100000 FORMAT CSVWithNames"
    settings={"max_threads":"2","max_memory_usage":str(512*1024**2),"max_execution_time":"120","wait_end_of_query":"0",
              "max_block_size":"8192","max_bytes_before_external_sort":str(128*1024**2),"max_temporary_data_on_disk_size_for_query":str(GIB),
              "query_id":ch.run_id+"-csv-export"}
    request=urllib.request.Request(ch.endpoint+"?"+urllib.parse.urlencode(settings),data=sql.encode(),method="POST",headers={"Authorization":ch.authorization})
    output=output_dir/("benchmark-export-"+uuid.uuid4().hex+".csv")
    begin=time.perf_counter();size=0;lines=0;digest=hashlib.sha256()
    try:
        with urllib.request.urlopen(request,timeout=150) as response,output.open("xb") as target:
            os.chmod(output,0o600)
            while data:=response.read(64*1024):
                size+=len(data);lines+=data.count(b"\n")
                if size>128*1024**2 or shutil.disk_usage(ROOT).free<host_min:raise StopBenchmark("Synthetic CSV export exceeded disk budget")
                target.write(data);digest.update(data)
            target.flush();os.fsync(target.fileno())
        if lines!=100001:raise StopBenchmark("Synthetic CSV export did not return exactly 100,000 rows plus header")
        return {"rows":100000,"bytes":size,"seconds":time.perf_counter()-begin,"sha256":digest.hexdigest(),"path":"temporary synthetic CSV removed after verification","pipeline":"direct ClickHouse CSV stream, separate from authenticated API export test"}
    except urllib.error.HTTPError as exc:
        code=exc.headers.get("X-ClickHouse-Exception-Code","unknown")
        raise StopBenchmark(f"Synthetic CSV export rejected (HTTP {exc.code}, exception {code})") from None
    except (urllib.error.URLError,TimeoutError):
        raise StopBenchmark("Synthetic CSV export request failed") from None
    finally:output.unlink(missing_ok=True)


def cleanup(args):
    """Delete only this script's verified synthetic table, retaining its receipt."""
    if not args.output.is_file():raise StopBenchmark("Cleanup requires the preserved benchmark receipt")
    report=json.loads(args.output.read_text())
    if report.get("table")!=TABLE or not report.get("checkpoints"):
        raise StopBenchmark("Cleanup requires completed checkpoint evidence for this exact table")
    ch=ClickHouse(args.env_file,args.endpoint)
    existing=ch.rows("SELECT comment FROM system.tables WHERE database='nebulalog' AND name='benchmark_events'")
    if not existing:
        print(json.dumps({"cleanup":"already_absent","table":TABLE}));return
    if existing[0]["comment"]!=MARKER:raise StopBenchmark("Cleanup refused: ownership marker mismatch")
    rows=ch.rows("SELECT count() AS rows,countIf(serial!='BENCHMARK' OR parse_status!='synthetic') AS foreign_rows FROM "+TABLE)[0]
    if int(rows["foreign_rows"]):raise StopBenchmark("Cleanup refused: table contains records outside the synthetic profile")
    active=ch.rows("SELECT count() AS count FROM system.processes WHERE startsWith(query,'INSERT INTO nebulalog.benchmark_events ')")[0]
    if int(active["count"]):raise StopBenchmark("Cleanup refused while synthetic inserts are active")
    receipt={"table":TABLE,"verified_rows":int(rows["rows"]),"before":table_state(ch),"started_at":datetime.now(timezone.utc).isoformat()}
    report["cleanup"]=receipt;save(args.output,report)
    ch.execute("DROP TABLE "+TABLE+" SYNC")
    if ch.rows("SELECT name FROM system.tables WHERE database='nebulalog' AND name='benchmark_events'"):
        raise StopBenchmark("Cleanup table absence could not be verified")
    receipt.update({"table_absent":True,"after":table_state(ch),"finished_at":datetime.now(timezone.utc).isoformat()})
    save(args.output,report)
    print(json.dumps({"cleanup":"verified","table":TABLE,"rows_removed":int(rows["rows"]),"host_free_bytes":receipt["after"]["host_free_bytes"]}))


def percentile(values,fraction):
    ordered=sorted(values);position=(len(ordered)-1)*fraction
    low=math.floor(position);high=math.ceil(position)
    return ordered[low]+(ordered[high]-ordered[low])*(position-low)


def benchmark_queries(ch,anchor,budget,host_min):
    base="log_type='traffic' AND received_at>=toDateTime64({from:String},6,'UTC') AND received_at<toDateTime64({to:String},6,'UTC')"
    params={"from":(anchor-timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S'),"to":(anchor+timedelta(seconds=1)).strftime('%Y-%m-%d %H:%M:%S')}
    predicates={"source_ip":"src_ip='10.20.0.42'","destination_ip":"dst_ip='198.51.100.43'",
      "cidr":"isIPAddressInRange(src_ip,'10.20.0.0/24')","application":"app='ssl'","rule":"rule='Benchmark policy 42'",
      "action":"action='deny'","firewall":"serial='BENCHMARK'","destination_port":"dst_port=443",
      "source_and_destination":"src_ip='10.20.0.42' AND dst_ip='198.51.100.43'","time_range":"1=1","denied_traffic":"action IN ('deny','drop')"}
    results=[]
    for range_name,hours in (("recent_1h",1),("24h",24),("7d",168)):
      params["from"]=(anchor-timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
      for name,predicate in predicates.items():
        safety(ch,budget,host_min)
        samples=[];rows_count=0
        sql="SELECT received_at,serial,src_ip,dst_ip,app,action,rule FROM "+TABLE+" WHERE "+base+" AND ("+predicate+") ORDER BY received_at DESC,id DESC LIMIT 200"
        for _ in range(3):
            start=time.perf_counter();rows=ch.rows(sql,params);samples.append((time.perf_counter()-start)*1000);rows_count=len(rows)
        results.append({"query":name,"range":range_name,"range_hours":hours,"limit":200,"returned_rows":rows_count,"samples_ms":samples,
                        "p50_ms":statistics.median(samples),"p95_ms":percentile(samples,.95),"cache":"first-and-warm mixed; caches not reset"})
    return results


def hardware():
    result={"os":platform.system(),"os_release":platform.release(),"architecture":platform.machine(),"logical_cpus":os.cpu_count(),"container_limits":{"clickhouse_cpus":3,"clickhouse_memory_bytes":3*GIB},"query_limits":{"threads":2,"memory_bytes":512*1024**2}}
    if platform.system()=="Darwin":
        for field,name in (("cpu_model","machdep.cpu.brand_string"),("physical_memory_bytes","hw.memsize")):
            proc=subprocess.run(["sysctl","-n",name],capture_output=True,text=True)
            if proc.returncode==0:result[field]=proc.stdout.strip()
    return result


def save(path,report):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    temporary=path.with_suffix(".pending")
    with temporary.open("w") as out:
        os.chmod(temporary,0o600);json.dump(report,out,indent=2,sort_keys=True);out.flush();os.fsync(out.fileno())
    os.replace(temporary,path)


def run(args):
    budget=args.disk_budget_gib*GIB;host_min=args.host_free_gib*GIB
    if args.disk_budget_gib>20 or args.host_free_gib<30:raise StopBenchmark("This checkout enforces at most 20 GiB benchmark data and at least 30 GiB host reserve")
    if args.batch>1000000 or args.batch<1:raise StopBenchmark("Batch must be 1..1,000,000 rows")
    if shutil.disk_usage(ROOT).free<host_min:raise StopBenchmark("Insufficient host physical reserve before benchmark")
    ch=ClickHouse(args.env_file,args.endpoint)
    previous=json.loads(args.output.read_text()) if args.resume and args.output.is_file() else {}
    report={"started_at":datetime.now(timezone.utc).isoformat(),"hardware":hardware(),"table":TABLE,"disk_budget_bytes":budget,"minimum_host_free_bytes":host_min,
            "dataset":{"wire_type":"TRAFFIC","raw_field_count":130,"synthetic":True,"native_insert_select":True,"parser_exercised":False,
                       "days":args.days,"reference_eps_equivalence":"row/time distribution only; not a 265 EPS listener test",
                       "addresses":"synthetic 10.20.0.0/16, 192.0.2.10 and 198.51.100.0/24","serial":"BENCHMARK",
                       "limitations":"Deterministic IDs and repeating sessions/user/application values compress better than many production mixes. Compression figures are not production sizing promises."},
            "checkpoints":previous.get("checkpoints",[]),"batches":previous.get("batches",[]),"status":"running",
            "prior_attempt":{"status":previous.get("status"),"reason":previous.get("reason"),"acknowledged_rows":previous.get("final_rows")},
            "insert_threads":1}
    existing=ch.rows("SELECT comment,total_rows FROM system.tables WHERE database='nebulalog' AND name='benchmark_events'")
    if existing:
        if existing[0]["comment"]!=MARKER:raise StopBenchmark("Existing benchmark table lacks the synthetic ownership marker")
        if not args.resume:raise StopBenchmark("Benchmark table already exists; use --resume after reviewing its state")
    else:
        ch.execute("CREATE TABLE "+TABLE+" AS nebulalog.events")
        ch.execute("ALTER TABLE "+TABLE+" MODIFY COMMENT '"+MARKER+"'")
    schema=ch.rows("SHOW CREATE TABLE "+TABLE)[0]["statement"]
    report["schema_sha256"]=hashlib.sha256(schema.encode()).hexdigest();report["schema"]=schema
    report["clickhouse_version"]=ch.rows("SELECT version() AS version")[0]["version"]
    container=subprocess.run(["docker","compose","--env-file",str(args.env_file),"ps","-q","clickhouse"],cwd=ROOT,capture_output=True,text=True,timeout=20)
    if container.returncode!=0 or not container.stdout.strip():raise StopBenchmark("Could not verify ClickHouse container resource limits")
    inspected=subprocess.run(["docker","inspect","--format",'{{json .HostConfig.NanoCpus}} {{json .HostConfig.Memory}}',container.stdout.strip()],capture_output=True,text=True,timeout=20)
    if inspected.returncode!=0:raise StopBenchmark("Could not inspect ClickHouse resource limits")
    cpus,memory=(int(v) for v in inspected.stdout.split())
    if cpus<=0 or cpus>3_000_000_000 or memory<=0 or memory>3*GIB:raise StopBenchmark("ClickHouse must be bounded to at most 3 CPUs and 3 GiB before benchmarking")
    report["hardware"]["verified_container_limits"]={"nanocpus":cpus,"memory_bytes":memory}
    sql=dataset_sql(args.days)
    anchor=datetime.fromisoformat(previous["dataset"]["anchor"]) if previous.get("dataset",{}).get("anchor") else datetime.now(timezone.utc).replace(microsecond=0)
    report["dataset"]["anchor"]=anchor.isoformat()
    inserted=table_state(ch)["rows"]
    next_id=int(ch.rows("SELECT if(count()=0,0,max(toUInt64(right(id,12)))+1) AS next_id FROM "+TABLE)[0]["next_id"])
    report["resumed_actual_rows"]=inserted
    report["resumed_next_unique_id"]=next_id
    try:
        for target in (10_000_000,100_000_000):
            if target>args.maximum_rows:break
            while inserted<target:
                wait_for_headroom(ch,budget,host_min)
                state=safety(ch,budget,host_min)
                batch=min(args.batch,target-inserted)
                if inserted:
                    # Reserve 50% above measured bytes/row for merge overlap and
                    # variation; safety is checked before AND after every batch.
                    estimated=state["active_bytes"]/inserted*batch*1.5
                    safety(ch,budget,host_min,projected_batch_bytes=math.ceil(estimated))
                begin=time.perf_counter()
                ch.execute(sql,{"offset":next_id,"batch":batch,"anchor":anchor.strftime('%Y-%m-%d %H:%M:%S'),"rows_per_day":math.ceil(10_000_000/args.days)},overrides={"max_threads":"1","max_block_size":"4096","max_insert_block_size":"4096"})
                inserted+=batch;next_id+=batch
                state=safety(ch,budget,host_min)
                if state["rows"]!=inserted:raise StopBenchmark("Actual synthetic row count differs from acknowledged batches; inspect before resuming")
                report["batches"].append({"rows":batch,"total_rows":inserted,"seconds":time.perf_counter()-begin,**state})
                save(args.output,report)
                print(json.dumps({"stage":"insert","total_rows":inserted,"table_bytes":state["bytes"],"host_free_bytes":state["host_free_bytes"]}),flush=True)
                time.sleep(2)
            state=safety(ch,budget,host_min)
            checkpoint={"rows":inserted,"storage":state,"bytes_per_event":state["active_bytes"]/inserted,
                        "compression_ratio":state["uncompressed_bytes"]/max(state["active_bytes"],1),
                        "queries":benchmark_queries(ch,anchor,budget,host_min)}
            report["checkpoints"].append(checkpoint);save(args.output,report)
            checkpoint["retention_test"]=retention_test(ch,budget,host_min)
            save(args.output,report)
            checkpoint["csv_export"]=csv_export(ch,args.output.parent,budget,host_min)
            save(args.output,report)
            if target==10_000_000 and args.maximum_rows>=100_000_000:
                projection=state["active_bytes"]*10*1.5
                report["projected_100m_bytes_with_merge_reserve"]=projection
                if projection>budget:raise StopBenchmark("Measured 10M footprint projects beyond 20 GiB at 100M with merge reserve; stopped before larger insert")
        report["status"]="complete"
    except StopBenchmark as exc:
        report["status"]="stopped_at_safety_limit";report["reason"]=str(exc)
    finally:
        report["finished_at"]=datetime.now(timezone.utc).isoformat()
        report["final_rows"]=inserted
        try:
            report["actual_final_state"]=table_state(ch)
            report["load_query_metrics"]=ch.rows("SELECT query_duration_ms,written_rows,written_bytes,memory_usage,ProfileEvents['UserTimeMicroseconds'] AS cpu_user_us,ProfileEvents['SystemTimeMicroseconds'] AS cpu_system_us FROM system.query_log WHERE query_id LIKE 'nebulalog-benchmark-%' AND type='QueryFinish' AND query LIKE 'INSERT INTO nebulalog.benchmark_events %' ORDER BY event_time")
        except StopBenchmark:report["final_measurement_error"]="ClickHouse unavailable for final measurement"
        save(args.output,report)
    print(json.dumps({"status":report["status"],"rows":inserted,"report":str(args.output.relative_to(ROOT)) if args.output.is_relative_to(ROOT) else args.output.name,"reason":report.get("reason")}),flush=True)
    return report


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    actions=p.add_mutually_exclusive_group(required=True)
    actions.add_argument("--run",action="store_true",help="Explicitly create/populate the isolated synthetic benchmark table")
    actions.add_argument("--cleanup",action="store_true",help="Delete only the marker-verified synthetic table after preserving checkpoint evidence")
    p.add_argument("--resume",action="store_true")
    p.add_argument("--env-file",type=Path,default=ROOT/".local/dev.env")
    p.add_argument("--endpoint",default="http://127.0.0.1:28123")
    p.add_argument("--maximum-rows",type=int,choices=(10_000_000,100_000_000),default=100_000_000)
    p.add_argument("--batch",type=int,default=1_000_000)
    p.add_argument("--days",type=int,choices=(30,90),default=30)
    p.add_argument("--disk-budget-gib",type=int,default=20)
    p.add_argument("--host-free-gib",type=int,default=30)
    p.add_argument("--output",type=Path,default=ROOT/".local/benchmark-results.json")
    a=p.parse_args()
    try:cleanup(a) if a.cleanup else run(a)
    except (StopBenchmark,ValueError,OSError) as exc:
        print(json.dumps({"status":"refused","reason":str(exc)}),file=sys.stderr);raise SystemExit(1)
