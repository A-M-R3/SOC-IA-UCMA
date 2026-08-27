import os
import sys

os.environ["HADOOP_HOME"] = r"C:\hadoop"
os.environ["hadoop.home.dir"] = r"C:\hadoop"
os.environ["PATH"] = r"C:\hadoop\bin;" + os.environ.get("PATH", "")

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField, StringType, 
    IntegerType, LongType, DoubleType, BooleanType
)

def main():
    print("=" * 60)
    print(" INICIANDO SPARK STRUCTURED STREAMING (SOC TELEMETRY)")
    print("=" * 60)

    spark = SparkSession.builder \
        .appName("SOC_Stream_Processor") \
        .config("spark.driver.memory", "2g") \
        .config("spark.jars.packages", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0") \
        .config("spark.driver.extraJavaOptions", "-Dhadoop.home.dir=C:/hadoop") \
        .config("spark.executor.extraJavaOptions", "-Dhadoop.home.dir=C:/hadoop") \
        .getOrCreate()

    spark.sparkContext.setLogLevel("ERROR")

    wazuh_schema = StructType([
        StructField("timestamp", StringType(), True),
        StructField("agent", StructType([
            StructField("id", StringType(), True),
            StructField("name", StringType(), True),
            StructField("ip", StringType(), True)
        ]), True),
        StructField("rule", StructType([
            StructField("id", StringType(), True),
            StructField("level", IntegerType(), True),
            StructField("description", StringType(), True)
        ]), True),
        StructField("data", StructType([
            StructField("uid", StringType(), True),
            StructField("ts", DoubleType(), True),
            StructField("src_ip", StringType(), True),
            StructField("src_port", IntegerType(), True),
            StructField("dst_ip", StringType(), True),
            StructField("dst_port", IntegerType(), True),
            StructField("proto", StringType(), True),
            StructField("service", StringType(), True),
            StructField("conn_state", StringType(), True),
            StructField("duration", DoubleType(), True),
            StructField("orig_bytes", LongType(), True),
            StructField("resp_bytes", LongType(), True),
            StructField("orig_pkts", IntegerType(), True),
            StructField("resp_pkts", IntegerType(), True),
            StructField("orig_ip_bytes", LongType(), True),
            StructField("resp_ip_bytes", LongType(), True),
            StructField("missed_bytes", LongType(), True),
            StructField("local_orig", BooleanType(), True),
            StructField("local_resp", BooleanType(), True)
        ]), True)
    ])

    df_kafka = spark.readStream \
        .format("kafka") \
        .option("kafka.bootstrap.servers", "localhost:9092") \
        .option("subscribe", "soc_telemetry") \
        .option("startingOffsets", "earliest") \
        .option("failOnDataLoss", "false") \
        .load()

    df_json = df_kafka.selectExpr("CAST(value AS STRING) as json_str")
    df_raw = df_json.select(F.from_json(F.col("json_str"), wazuh_schema).alias("w"))

    df_flattened = df_raw.select(
        F.col("w.timestamp").alias("@timestamp"),
        F.col("w.agent.id").alias("agent_id"),
        F.col("w.agent.name").alias("agent_name"),
        F.col("w.agent.ip").alias("agent_ip"),
        F.col("w.rule.id").cast(IntegerType()).alias("rule_id"),
        F.col("w.rule.level").alias("rule_level"),
        F.col("w.rule.description").alias("rule_description"),
        F.col("w.data.uid").alias("uid"),
        F.col("w.data.ts").alias("zeek_timestamp"),
        F.col("w.data.src_ip").alias("src_ip"),
        F.col("w.data.src_port").alias("src_port"),
        F.col("w.data.dst_ip").alias("dst_ip"),
        F.col("w.data.dst_port").alias("dst_port"),
        F.col("w.data.proto").alias("protocol"),
        F.col("w.data.service").alias("service"),
        F.col("w.data.conn_state").alias("connection_state"),
        F.col("w.data.duration").alias("duration"),
        F.col("w.data.orig_bytes").alias("orig_bytes"),
        F.col("w.data.resp_bytes").alias("resp_bytes"),
        F.col("w.data.orig_pkts").alias("orig_packets"),
        F.col("w.data.resp_pkts").alias("resp_packets"),
        F.col("w.data.orig_ip_bytes").alias("orig_ip_bytes"),
        F.col("w.data.resp_ip_bytes").alias("resp_ip_bytes"),
        F.col("w.data.missed_bytes").alias("missed_bytes"),
        F.col("w.data.local_orig").alias("local_orig"),
        F.col("w.data.local_resp").alias("local_resp")
    )

    df_final = df_flattened.na.fill(0, subset=[
        "src_port", "dst_port", "orig_bytes", "resp_bytes", 
        "orig_packets", "resp_packets", "orig_ip_bytes", "resp_ip_bytes", "missed_bytes"
    ])
    df_final = df_final.na.fill(0.0, subset=["zeek_timestamp", "duration"])
    df_final = df_final.na.fill(False, subset=["local_orig", "local_resp"])
    df_final = df_final.na.fill("unknown", subset=["protocol", "service", "connection_state"])

    query = df_final.writeStream \
        .outputMode("append") \
        .format("console") \
        .option("truncate", "false") \
        .trigger(processingTime="2 seconds") \
        .start()

    print("Procesador activo en Spark Structured Streaming, consumiendo eventos desde Kafka...")
    query.awaitTermination()

if __name__ == "__main__":
    main()