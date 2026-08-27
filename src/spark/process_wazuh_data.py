import sys
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import StructType, StructField, StringType, IntegerType, DoubleType, BooleanType

spark = SparkSession.builder \
    .appName("SOC_Data_Processor") \
    .config("spark.driver.memory", "2g") \
    .getOrCreate()

spark.sparkContext.setLogLevel("ERROR")

wazuh_path = "docs/schemas/wazuh_zeek_historico.csv"
output_csv = "docs/schemas/dataset_procesado"

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

df_raw = spark.read.option("header", "true") \
    .option("multiLine", "true") \
    .option("escape", '"') \
    .schema(custom_schema) \
    .csv(wazuh_path)

df_final = df_raw.na.fill(0, subset=["src_port", "dst_port", "orig_bytes", "resp_bytes", "orig_packets", "resp_packets", "orig_ip_bytes", "resp_ip_bytes", "missed_bytes"])
df_final = df_final.na.fill(0.0, subset=["zeek_timestamp", "duration"])
df_final = df_final.na.fill(False, subset=["local_orig", "local_resp"])

print("Muestra inicial de registros validados desde Wazuh:")
df_final.select("@timestamp", "agent_name", "rule_id", "src_ip", "dst_port", "duration", "orig_bytes").show(20, truncate=False)

df_final.coalesce(1).write.mode("overwrite").option("header", "true").option("timestampFormat", "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").csv(output_csv)

print("Proceso de validacion y almacenamiento completado.")

spark.stop()