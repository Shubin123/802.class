"""Check the features in the zipped parquet."""
import zipfile, io, pandas as pd

zf = zipfile.ZipFile("../data/dataset_output/dataset.parquet.zip")
print("Files in zip:", zf.namelist())
with zf.open(zf.namelist()[0]) as f:
    df = pd.read_parquet(io.BytesIO(f.read()))

print("Shape:", df.shape)
print("Columns:", list(df.columns))

exclude = {'label', 'timestamp', '_blk', '_fid'}
feature_cols = [c for c in df.columns if c not in exclude]
print("Feature cols:", feature_cols)
print("Num features:", len(feature_cols))

# Check which are constant
for c in feature_cols:
    try:
        u = df[c].nunique()
        print(f"  {c:15s}  nunique={u}  {'CONSTANT' if u <= 1 else ''}")
    except:
        print(f"  {c:15s}  (unhashable)")

valid = [c for c in feature_cols if df[c].nunique() > 1]
print("\nValid (non-constant) features:", valid)
print("Count:", len(valid))

print("\nLabels:", sorted(df['label'].unique()))
