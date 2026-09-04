import os
import sys
import json
import csv
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from pyspark.sql import SparkSession
from pyspark.sql.functions import col

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = "wazuh-alerts"
OUTPUT_DIR = "docs/schemas/dataset_enriquecido"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "dataset_completo_unificado.csv")

os.makedirs(OUTPUT_DIR, exist_ok=True)

spark = SparkSession.builder \
    .appName("WazuhCanonicalCleanStreamProcessor") \
    .config("spark.jars.packages", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0") \
    .config("spark.sql.streaming.forceDeleteTempCheckpointLocation", "true") \
    .getOrCreate()

spark.sparkContext.setLogLevel("ERROR")

df_raw = spark.readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP_SERVERS) \
    .option("subscribe", KAFKA_TOPIC) \
    .option("startingOffsets", "earliest") \
    .option("failOnDataLoss", "false") \
    .load()

df_stream = df_raw.select(col("value").cast("string").alias("raw_json"))

def sanitize_text(val):
    if val is None:
        return None
    if isinstance(val, str):
        return " ".join(val.replace("\r", " ").replace("\n", " ").split())
    return val

def parse_wazuh_event(raw_dict):
    res = {}
    
    ts = raw_dict.get("timestamp") or raw_dict.get("timestamp_utc") or raw_dict.get("@timestamp")
    if ts:
        dt = pd.to_datetime(ts, errors="coerce", utc=True)
        if pd.notnull(dt):
            res["timestamp_cest"] = dt.tz_convert("Europe/Madrid").strftime("%Y-%m-%d %H:%M:%S CEST")
            res["timestamp_utc"] = str(ts)
        else:
            res["timestamp_cest"] = raw_dict.get("timestamp_cest", str(ts))
            res["timestamp_utc"] = str(ts)
    else:
        res["timestamp_cest"] = raw_dict.get("timestamp_cest")
        res["timestamp_utc"] = None

    agent = raw_dict.get("agent", {}) if isinstance(raw_dict.get("agent"), dict) else {}
    res["agent_id"] = sanitize_text(agent.get("id") or raw_dict.get("agent_id"))
    res["agent_name"] = sanitize_text(agent.get("name") or raw_dict.get("agent_name"))
    res["agent_ip"] = sanitize_text(agent.get("ip") or raw_dict.get("agent_ip"))

    rule = raw_dict.get("rule", {}) if isinstance(raw_dict.get("rule"), dict) else {}
    res["rule_id"] = sanitize_text(rule.get("id") or raw_dict.get("rule_id"))
    res["rule_level"] = rule.get("level") or raw_dict.get("rule_level", 0)
    res["rule_description"] = sanitize_text(rule.get("description") or raw_dict.get("rule_description"))
    res["rule_firedtimes"] = rule.get("firedtimes") or raw_dict.get("rule_firedtimes", 1)
    
    rg = rule.get("groups") or raw_dict.get("rule_groups", [])
    res["rule_groups"] = ",".join(rg) if isinstance(rg, list) else sanitize_text(rg)
    
    mitre = rule.get("mitre", {}) if isinstance(rule.get("mitre"), dict) else {}
    res["mitre_id"] = ",".join(mitre.get("id", [])) if isinstance(mitre.get("id"), list) else sanitize_text(mitre.get("id") or raw_dict.get("mitre_id"))
    res["mitre_tactic"] = ",".join(mitre.get("tactic", [])) if isinstance(mitre.get("tactic"), list) else sanitize_text(mitre.get("tactic") or raw_dict.get("mitre_tactic"))
    res["mitre_technique"] = ",".join(mitre.get("technique", [])) if isinstance(mitre.get("technique"), list) else sanitize_text(mitre.get("technique") or raw_dict.get("mitre_technique"))
    
    pci = rule.get("pci_dss") or raw_dict.get("compliance_pci", [])
    res["compliance_pci"] = ",".join(pci) if isinstance(pci, list) else sanitize_text(pci)
    
    gdpr = rule.get("gdpr") or raw_dict.get("compliance_gdpr", [])
    res["compliance_gdpr"] = ",".join(gdpr) if isinstance(gdpr, list) else sanitize_text(gdpr)

    predecoder = raw_dict.get("predecoder", {}) if isinstance(raw_dict.get("predecoder"), dict) else {}
    res["program_name"] = sanitize_text(predecoder.get("program_name") or raw_dict.get("program_name"))

    data = raw_dict.get("data", {}) if isinstance(raw_dict.get("data"), dict) else {}
    res["srcuser"] = sanitize_text(data.get("srcuser") or raw_dict.get("srcuser"))
    res["dstuser"] = sanitize_text(data.get("dstuser") or raw_dict.get("dstuser"))
    res["uid"] = sanitize_text(data.get("uid") or raw_dict.get("uid"))
    res["command"] = sanitize_text(data.get("command") or raw_dict.get("command"))

    syscheck = raw_dict.get("syscheck", {}) if isinstance(raw_dict.get("syscheck"), dict) else {}
    res["file_path"] = sanitize_text(syscheck.get("path") or raw_dict.get("file_path"))
    res["fim_event"] = sanitize_text(syscheck.get("event") or raw_dict.get("fim_event"))
    res["file_sha256"] = sanitize_text(syscheck.get("sha256_after") or raw_dict.get("file_sha256"))
    res["file_size"] = syscheck.get("size_after") or raw_dict.get("file_size")

    virustotal = data.get("virustotal", {}) if isinstance(data.get("virustotal"), dict) else {}
    res["vt_positives"] = virustotal.get("positives") or raw_dict.get("vt_positives")
    res["vt_total"] = virustotal.get("total") or raw_dict.get("vt_total")
    res["vt_malicious"] = virustotal.get("malicious") or raw_dict.get("vt_malicious")
    vt_src = virustotal.get("source", {}) if isinstance(virustotal.get("source"), dict) else {}
    res["vt_file"] = sanitize_text(vt_src.get("file") or raw_dict.get("vt_file"))
    res["vt_permalink"] = sanitize_text(virustotal.get("permalink") or raw_dict.get("vt_permalink"))

    net_id = data.get("id", {}) if isinstance(data.get("id"), dict) else {}
    res["src_ip"] = sanitize_text(net_id.get("orig_h") or raw_dict.get("src_ip"))
    res["src_port"] = net_id.get("orig_p") or raw_dict.get("src_port")
    res["dst_ip"] = sanitize_text(net_id.get("resp_h") or raw_dict.get("dst_ip"))
    res["dst_port"] = net_id.get("resp_p") or raw_dict.get("dst_port")
    res["protocol"] = sanitize_text(data.get("proto") or raw_dict.get("protocol"))
    res["service"] = sanitize_text(data.get("service") or raw_dict.get("service"))
    res["duration"] = data.get("duration") or raw_dict.get("duration")
    res["orig_bytes"] = data.get("orig_bytes") or raw_dict.get("orig_bytes")
    res["resp_bytes"] = data.get("resp_bytes") or raw_dict.get("resp_bytes")
    res["orig_pkts"] = data.get("orig_pkts") or raw_dict.get("orig_pkts")
    res["resp_pkts"] = data.get("resp_pkts") or raw_dict.get("resp_pkts")
    res["conn_state"] = sanitize_text(data.get("conn_state") or raw_dict.get("conn_state"))

    if res["vt_positives"] is not None:
        res["event_type"] = "host_virustotal"
    elif res["file_path"] is not None:
        res["event_type"] = "host_fim"
    elif res["srcuser"] is not None or res["dstuser"] is not None or res["program_name"] == "sudo":
        res["event_type"] = "host_auth"
    elif res["src_ip"] is not None or res["protocol"] is not None:
        res["event_type"] = "network_zeek"
    else:
        res["event_type"] = raw_dict.get("event_type", "host_system")

    res["location"] = sanitize_text(raw_dict.get("location"))
    res["full_log"] = sanitize_text(raw_dict.get("full_log"))

    return res

def process_and_persist_batch(batch_df, batch_id):
    if batch_df.isEmpty():
        return

    raw_rows = batch_df.select("raw_json").collect()
    parsed_events = []
    for r in raw_rows:
        if r.raw_json:
            try:
                data_obj = json.loads(r.raw_json) if isinstance(r.raw_json, str) else r.raw_json
                ev = parse_wazuh_event(data_obj)
                if ev["event_type"] == "network_zeek" and (ev.get("dst_port") == 5353 or ev.get("src_port") == 5353):
                    continue
                parsed_events.append(ev)
            except Exception:
                pass

    if not parsed_events:
        return

    pdf = pd.DataFrame(parsed_events)

    if os.path.exists(OUTPUT_CSV):
        try:
            existing_df = pd.read_csv(OUTPUT_CSV, on_bad_lines="skip")
            combined_df = pd.concat([existing_df, pdf], ignore_index=True)
            if "timestamp_utc" in combined_df.columns and "full_log" in combined_df.columns:
                combined_df = combined_df.drop_duplicates(subset=["timestamp_utc", "full_log"], keep="last")
        except Exception:
            combined_df = pdf.copy()
    else:
        combined_df = pdf.copy()

    feature_matrix = pd.DataFrame(index=combined_df.index)
    feature_matrix["rule_level"] = pd.to_numeric(combined_df["rule_level"], errors="coerce").fillna(0)
    feature_matrix["rule_firedtimes"] = pd.to_numeric(combined_df["rule_firedtimes"], errors="coerce").fillna(1)
    feature_matrix["vt_positives"] = pd.to_numeric(combined_df["vt_positives"], errors="coerce").fillna(0)
    feature_matrix["duration"] = pd.to_numeric(combined_df["duration"], errors="coerce").fillna(0)
    feature_matrix["orig_bytes"] = pd.to_numeric(combined_df["orig_bytes"], errors="coerce").fillna(0)
    feature_matrix["resp_bytes"] = pd.to_numeric(combined_df["resp_bytes"], errors="coerce").fillna(0)
    feature_matrix["is_sudo"] = np.where(combined_df["program_name"] == "sudo", 1, 0)
    feature_matrix["is_root"] = np.where(combined_df["dstuser"] == "root", 1, 0)

    if len(combined_df) >= 2:
        model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        model.fit(feature_matrix)
        raw_predictions = model.predict(feature_matrix)
        decision_scores = model.decision_function(feature_matrix)
        score_range = decision_scores.max() - decision_scores.min()
        if score_range == 0:
            anomaly_scores = np.where(feature_matrix["rule_level"] >= 7, 0.8500, 0.0500)
        else:
            anomaly_scores = 1.0 - (decision_scores - decision_scores.min()) / score_range

        combined_df["anomaly_score"] = np.round(anomaly_scores, 4)
        combined_df["is_anomaly"] = np.where(raw_predictions == -1, 1, 0)
    else:
        combined_df["anomaly_score"] = 0.0
        combined_df["is_anomaly"] = 0

    ordered_columns = [
        "timestamp_cest", "timestamp_utc", "event_type", "agent_id", "agent_name", "agent_ip",
        "rule_id", "rule_level", "rule_description", "rule_firedtimes", "rule_groups",
        "mitre_id", "mitre_tactic", "mitre_technique", "compliance_pci", "compliance_gdpr",
        "program_name", "srcuser", "dstuser", "uid", "command",
        "file_path", "fim_event", "file_sha256", "file_size",
        "vt_positives", "vt_total", "vt_malicious", "vt_file", "vt_permalink",
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "service",
        "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "conn_state",
        "location", "full_log", "anomaly_score", "is_anomaly"
    ]
    
    final_cols = [c for c in ordered_columns if c in combined_df.columns]
    combined_df = combined_df[final_cols]
    combined_df.to_csv(OUTPUT_CSV, index=False, quoting=csv.QUOTE_MINIMAL)

    print(f"\n[MICRO-BATCH {batch_id}] Total eventos estructurados: {len(combined_df)}")
    summary_cols = ["timestamp_cest", "agent_name", "event_type", "rule_id", "rule_level", "vt_positives", "src_ip", "dst_port", "anomaly_score", "is_anomaly"]
    valid_summary = [c for c in summary_cols if c in combined_df.columns]
    print(combined_df[valid_summary].tail(5).to_string(index=False))

query = df_stream.writeStream \
    .foreachBatch(process_and_persist_batch) \
    .start()

query.awaitTermination()