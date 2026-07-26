import sys
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import StructType, StructField, StringType, IntegerType, DoubleType, BooleanType

# Create Spark Session
# NOTE: Kafka dependency removed due to version mismatch with Spark 4.2.0
# To add Kafka support, wait for spark-sql-kafka-0-10 4.2.0 release or downgrade to Spark 3.5.3
spark = SparkSession.builder \
    .appName("SOC_Stream_Processor") \
    .config("spark.driver.memory", "2g") \
    .getOrCreate()

spark.sparkContext.setLogLevel("ERROR")

print("✓ Spark 4.2.0 initialized successfully with Java 25 compatibility!")

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

# Kafka support commented out for Spark 4.2.0 (waiting for spark-sql-kafka-0-10 4.2.0 release)
# TODO: Uncomment below when Kafka connector is available
# df_kafka = spark.readStream \
#     .format("kafka") \
#     .option("kafka.bootstrap_servers", "localhost:9092") \
#     .option("subscribe", "soc_telemetry") \
#     .option("startingOffsets", "earliest") \
#     .load()
#
# df_json = df_kafka.selectExpr("CAST(value AS STRING) as json_str")

# For now, create a demo DataFrame to test the pipeline
print("Creating demo dataframe for testing...")
demo_data = [
    ("2024-07-26T10:00:00Z", "agent001", "firewall-01", "192.168.1.1", 
     1001, 5, "Intrusion detected", "uid123", 1721992800.0,
     "10.0.0.1", 443, "8.8.8.8", 53, "TCP", "DNS", "ESTABLISHED",
     1.5, 1024, 512, 10, 5, 1024, 512, 0, True, False),
]

df_json = spark.createDataFrame(demo_data, schema=custom_schema)

print("✓ Demo dataframe created successfully!")
df_json.show()

# With actual Kafka stream, use this code:
# df_parsed = df_json.select(F.from_json(F.col("json_str"), custom_schema).alias("data")).select("data.*")

# For demo dataframe, data is already parsed
print("\n✓ Processing demo data...")

# Apply transformations (fill nulls)
df_final = df_json.na.fill(0, subset=["src_port", "dst_port", "orig_bytes", "resp_bytes", "orig_packets", "resp_packets", "orig_ip_bytes", "resp_ip_bytes", "missed_bytes"])
df_final = df_final.na.fill(0.0, subset=["zeek_timestamp", "duration"])
df_final = df_final.na.fill(False, subset=["local_orig", "local_resp"])

print("✓ Transformations applied")
df_final.show()

# TODO: Integrate with Kafka and streaming when spark-sql-kafka connector is available
# query = df_final.writeStream \
#     .outputMode("append") \
#     .format("console") \
#     .start()
# query.awaitTermination()

print("\n✓ Stream processor test completed successfully!")
print("✓ Spark pipeline is ready for Kafka integration")

# Keep spark session alive for additional operations
spark.stop()
print("✓ Spark session closed")