import sys
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import StructType, StructField, StringType, IntegerType, DoubleType, BooleanType

spark = SparkSession.builder \
    .appName("SOC_Stream_Processor") \
    .config("spark.driver.memory", "2g") \
    .config("spark.jars.packages", "org.apache.spark:spark-sql-kafka-0-10_2.13:4.2.0") \
    .getOrCreate()

spark.sparkContext.setLogLevel("ERROR")

custom_schema = StructType([
    StructField("@timestamp", StringType(), True),
    StructField("agent_id", StringType(), True),
    StructField("agent_name", StringType(), True),
    StructField("agent_ip", StringType(), True),
    StructField("rule_id", IntegerType(), True),
    StructField("rule_level", IntegerType(), True),
    StructField("rule_description", StringType(), True),
    StructField("uid", StringType(), True),
    StructField("zeek_timestamp", DoubleType(), True),
    StructField("src_ip", StringType(), True),
    StructField("src_port", IntegerType(), True),
    StructField("dst_ip", StringType(), True),
    StructField("dst_port", IntegerType(), True),
    StructField("protocol", StringType(), True),
    StructField("service", StringType(), True),
    StructField("connection_state", StringType(), True),
    StructField("duration", DoubleType(), True),
    StructField("orig_bytes", IntegerType(), True),
    StructField("resp_bytes", IntegerType(), True),
    StructField("orig_packets", IntegerType(), True),
    StructField("resp_packets", IntegerType(), True),
    StructField("orig_ip_bytes", IntegerType(), True),
    StructField("resp_ip_bytes", IntegerType(), True),
    StructField("missed_bytes", IntegerType(), True),
    StructField("local_orig", BooleanType(), True),
    StructField("local_resp", BooleanType(), True)
])

df_kafka = spark.readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "localhost:9092") \
    .option("subscribe", "soc_telemetry") \
    .option("startingOffsets", "earliest") \
    .load()

df_json = df_kafka.selectExpr("CAST(value AS STRING) as json_str")
df_parsed = df_json.select(F.from_json(F.col("json_str"), custom_schema).alias("data")).select("data.*")

df_final = df_parsed.na.fill(0, subset=["src_port", "dst_port", "orig_bytes", "resp_bytes", "orig_packets", "resp_packets", "orig_ip_bytes", "resp_ip_bytes", "missed_bytes"])
df_final = df_final.na.fill(0.0, subset=["zeek_timestamp", "duration"])
df_final = df_final.na.fill(False, subset=["local_orig", "local_resp"])

query = df_final.writeStream \
    .outputMode("append") \
    .format("console") \
    .start()

print("Procesador activo en Spark 4.2.0, consumiendo eventos desde Kafka...")
query.awaitTermination()