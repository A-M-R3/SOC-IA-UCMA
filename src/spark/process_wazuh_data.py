import os
import sys
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import IntegerType, DoubleType

spark = SparkSession.builder \
    .appName("SOC_Data_Processor") \
    .config("spark.driver.memory", "2g") \
    .getOrCreate()

spark.sparkContext.setLogLevel("ERROR")

wazuh_path = "docs/schemas/dataset_enriquecido/dataset_completo_unificado.csv"
output_csv = "docs/schemas/dataset_procesado"

df_raw = spark.read.option("header", "true") \
    .option("multiLine", "true") \
    .option("escape", '"') \
    .csv(wazuh_path)

numeric_cols = ["rule_level", "rule_firedtimes", "vt_positives", "src_port", "dst_port", "orig_bytes", "resp_bytes", "is_anomaly"]
for c in numeric_cols:
    if c in df_raw.columns:
        df_raw = df_raw.withColumn(c, F.col(c).cast(IntegerType()))

double_cols = ["duration", "anomaly_score"]
for c in double_cols:
    if c in df_raw.columns:
        df_raw = df_raw.withColumn(c, F.col(c).cast(DoubleType()))

fill_int = {c: 0 for c in numeric_cols if c in df_raw.columns}
fill_double = {c: 0.0 for c in double_cols if c in df_raw.columns}
df_final = df_raw.na.fill(fill_int).na.fill(fill_double)

print("Muestra inicial de registros validados desde Wazuh:")
available_cols = [c for c in ["timestamp_cest", "agent_name", "rule_id", "rule_level", "src_ip", "dst_port", "duration", "orig_bytes", "anomaly_score", "is_anomaly"] if c in df_final.columns]
df_final.select(available_cols).show(20, truncate=False)

df_final.coalesce(1).write.mode("overwrite").option("header", "true").csv(output_csv)

print("Proceso de validacion y almacenamiento completado.")

spark.stop()