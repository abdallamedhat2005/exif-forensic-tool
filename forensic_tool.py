#!/usr/bin/env python3
"""
Digital Image Metadata Extraction & Geolocation Analysis Tool
CET333 - Advanced Digital Forensics | Spring 2026
Elsewedy University of Technology
"""

import os, csv, json, argparse, hashlib
from datetime import datetime
from pathlib import Path

import exifread
import pandas as pd
import folium
from folium.plugins import MarkerCluster, TimestampedGeoJson
from PIL import Image


# ─────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_ratio(value):
    s = str(value)
    if "/" in s:
        a, b = s.split("/")
        return float(a) / float(b) if float(b) != 0 else 0.0
    return float(s)

def dms_to_decimal(dms_tag, ref_tag):
    try:
        parts = [p.strip() for p in str(dms_tag).replace("[","").replace("]","").split(",")]
        if len(parts) != 3: return None
        dec = parse_ratio(parts[0]) + parse_ratio(parts[1])/60 + parse_ratio(parts[2])/3600
        if str(ref_tag).strip() in ["S","W"]: dec = -dec
        return round(dec, 7)
    except Exception:
        return None

def ts_to_iso(ts):
    """Convert EXIF timestamp 2026:03:14 10:30:00 to ISO 2026-03-14T10:30:00"""
    try:
        return datetime.strptime(str(ts), "%Y:%m:%d %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None


# ─────────────────────────────────────────
# EXTRACTOR
# ─────────────────────────────────────────

def extract_record(image_path):
    path_str  = str(image_path)
    file_hash = sha256_file(path_str)
    file_size = os.path.getsize(path_str)
    tags      = {}
    anomalies = []

    try:
        with Image.open(path_str) as im:
            fmt = im.format
            img_width, img_height = im.size
    except Exception:
        fmt, img_width, img_height = "UNKNOWN", None, None

    if fmt == "PNG":
        anomalies.append("PNG format — EXIF/GPS rarely present")
    else:
        try:
            with open(path_str, "rb") as f:
                raw = exifread.process_file(f, details=False)
            tags = {str(k): str(v) for k, v in raw.items()}
        except Exception as e:
            anomalies.append(f"EXIF read error: {e}")

    timestamp  = tags.get("EXIF DateTimeOriginal") or tags.get("Image DateTime")
    make       = tags.get("Image Make")
    model      = tags.get("Image Model")
    software   = tags.get("Image Software")
    flash      = tags.get("EXIF Flash")
    focal      = tags.get("EXIF FocalLength")
    iso        = tags.get("EXIF ISOSpeedRatings")
    width      = tags.get("EXIF ExifImageWidth")  or tags.get("Image ImageWidth")  or str(img_width)
    height     = tags.get("EXIF ExifImageLength") or tags.get("Image ImageLength") or str(img_height)
    orientation= tags.get("Image Orientation")
    exposure   = tags.get("EXIF ExposureTime")
    aperture   = tags.get("EXIF FNumber")

    lat = dms_to_decimal(tags.get("GPS GPSLatitude"), tags.get("GPS GPSLatitudeRef"))
    lon = dms_to_decimal(tags.get("GPS GPSLongitude"), tags.get("GPS GPSLongitudeRef"))
    alt = None
    if tags.get("GPS GPSAltitude"):
        try: alt = round(parse_ratio(tags["GPS GPSAltitude"]), 2)
        except: pass

    # Anomaly detection — comprehensive
    if not tags:
        anomalies.append("⚠ No EXIF metadata — possible intentional stripping")
    if not timestamp:
        anomalies.append("⚠ Missing original timestamp")
    if lat is None or lon is None:
        anomalies.append("⚠ Missing GPS coordinates")
    if software:
        anomalies.append(f"⚠ Software tag: {software} — possible post-processing")
    if make is None and model is None and tags:
        anomalies.append("⚠ No camera make/model — suspicious")

    record = {
        "file_name": os.path.basename(path_str),
        "file_size_kb": round(file_size/1024, 1),
        "format": fmt,
        "sha256": file_hash,
        "timestamp": timestamp,
        "timestamp_iso": ts_to_iso(timestamp),
        "camera_make": make,
        "camera_model": model,
        "software": software,
        "flash": flash,
        "focal_length": focal,
        "iso": iso,
        "exposure": exposure,
        "aperture": aperture,
        "image_width": width,
        "image_height": height,
        "orientation": orientation,
        "gps_latitude": lat,
        "gps_longitude": lon,
        "gps_altitude": alt,
        "has_exif": bool(tags),
        "anomaly_flags": " | ".join(anomalies) if anomalies else "None",
        "anomaly_count": len(anomalies),
    }
    return record, tags


# ─────────────────────────────────────────
# MAP WITH TIMELINE
# ─────────────────────────────────────────

def build_map(df, output_file):
    geo = df.dropna(subset=["gps_latitude","gps_longitude"])
    if geo.empty:
        return None

    center = [geo["gps_latitude"].mean(), geo["gps_longitude"].mean()]
    m = folium.Map(location=center, zoom_start=12, tiles="OpenStreetMap")

    # Layer 1: Clustered markers
    cluster = MarkerCluster(name="📍 All Evidence").add_to(m)
    for _, row in geo.iterrows():
        color = "red" if row["anomaly_count"] > 1 else "orange" if row["anomaly_count"] == 1 else "blue"
        popup_html = f"""
        <div style="font-family:Arial,sans-serif;min-width:220px;font-size:13px">
          <div style="background:#0b3d5c;color:white;padding:8px 12px;border-radius:4px 4px 0 0;font-weight:bold">
            📁 {row["file_name"]}
          </div>
          <div style="padding:10px 12px;border:1px solid #ddd;border-top:none;border-radius:0 0 4px 4px">
            🕐 <b>Time:</b> {row["timestamp"] or "Unknown"}<br>
            📷 <b>Camera:</b> {(row["camera_make"] or "")} {(row["camera_model"] or "Unknown")}<br>
            📍 <b>GPS:</b> {row["gps_latitude"]}, {row["gps_longitude"]}<br>
            {"🏔️ <b>Alt:</b> " + str(row["gps_altitude"]) + "m<br>" if row["gps_altitude"] else ""}
            🔐 <b>SHA-256:</b><br>
            <span style="font-size:10px;word-break:break-all;color:#555">{row["sha256"]}</span><br>
            {"<br>⚠️ <b style=\'color:#c0392b\'>"+row["anomaly_flags"]+"</b>" if row["anomaly_flags"] != "None" else "<br>✅ <b style=\'color:#27ae60\'>No anomalies detected</b>"}
          </div>
        </div>"""
        folium.Marker(
            location=[row["gps_latitude"], row["gps_longitude"]],
            popup=folium.Popup(popup_html, max_width=320),
            tooltip=f"📁 {row['file_name']} | {row['timestamp'] or 'No time'}",
            icon=folium.Icon(color=color, icon="camera", prefix="fa")
        ).add_to(cluster)

    # Layer 2: Timeline path (line connecting sorted images)
    timeline_geo = geo.dropna(subset=["timestamp_iso"]).sort_values("timestamp_iso")
    if len(timeline_geo) >= 2:
        coords = [[r["gps_latitude"], r["gps_longitude"]] for _, r in timeline_geo.iterrows()]
        folium.PolyLine(
            locations=coords,
            color="#e74c3c",
            weight=3,
            opacity=0.8,
            tooltip="📅 Investigation Timeline Path",
            dash_array="8"
        ).add_to(m)

        # Numbered timeline markers
        tl_group = folium.FeatureGroup(name="📅 Timeline Order").add_to(m)
        for idx, (_, row) in enumerate(timeline_geo.iterrows(), 1):
            folium.Marker(
                location=[row["gps_latitude"], row["gps_longitude"]],
                tooltip=f"#{idx} — {row['file_name']} @ {row['timestamp']}",
                icon=folium.DivIcon(
                    html=f'''<div style="background:#e74c3c;color:white;border-radius:50%;
                               width:24px;height:24px;display:flex;align-items:center;
                               justify-content:center;font-weight:bold;font-size:12px;
                               border:2px solid white;box-shadow:0 2px 4px rgba(0,0,0,0.3)">{idx}</div>''',
                    icon_size=(24, 24),
                    icon_anchor=(12, 12)
                )
            ).add_to(tl_group)

    folium.LayerControl(collapsed=False).add_to(m)

    # Legend
    legend_html = """
    <div style="position:fixed;bottom:30px;left:30px;z-index:9999;background:white;
                padding:12px 16px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.2);font-size:13px">
      <b>🗺️ Map Legend</b><br>
      <span style="color:#2980b9">🔵</span> Clean image<br>
      <span style="color:#e67e22">🟠</span> Minor anomaly<br>
      <span style="color:#c0392b">🔴</span> Suspicious<br>
      <span style="color:#e74c3c">— —</span> Timeline path
    </div>"""
    m.get_root().html.add_child(folium.Element(legend_html))
    m.save(output_file)
    return output_file


# ─────────────────────────────────────────
# HTML REPORT
# ─────────────────────────────────────────

def generate_report(df, output_file, case_id):
    total     = len(df)
    with_gps  = df["gps_latitude"].notna().sum()
    anomalous = (df["anomaly_count"] > 0).sum()
    clean     = total - anomalous

    timeline_rows = ""
    for i, row in df.iterrows():
        ts = row["timestamp"] or "—"
        gps = f"{row['gps_latitude']}, {row['gps_longitude']}" if row["gps_latitude"] else "—"
        timeline_rows += f"""
        <div class="tl-item">
          <div class="tl-dot {'tl-red' if row['anomaly_count']>1 else 'tl-orange' if row['anomaly_count']==1 else 'tl-blue'}"></div>
          <div class="tl-content">
            <div class="tl-title">📁 {row["file_name"]}</div>
            <div class="tl-meta">🕐 {ts} &nbsp;|&nbsp; 📍 {gps} &nbsp;|&nbsp; 📷 {row["camera_make"] or "?"} {row["camera_model"] or ""}</div>
            {"<div class=\"tl-flag\">⚠️ "+row["anomaly_flags"]+"</div>" if row["anomaly_flags"] != "None" else "<div class=\"tl-ok\">✅ No anomalies</div>"}
          </div>
        </div>"""

    table_rows = ""
    for _, row in df.iterrows():
        flag_color = "#c0392b" if row["anomaly_count"]>1 else "#e67e22" if row["anomaly_count"]==1 else "#27ae60"
        table_rows += f"""
        <tr>
          <td><b>{row["file_name"]}</b><br><small>{row["format"]} · {row["file_size_kb"]} KB</small></td>
          <td>{row["timestamp"] or "—"}</td>
          <td>{(row["camera_make"] or "—")} {row["camera_model"] or ""}</td>
          <td>{row["gps_latitude"] or "—"}<br>{row["gps_longitude"] or "—"}</td>
          <td>{row["gps_altitude"] or "—"}</td>
          <td style="color:{flag_color};font-weight:bold">{row["anomaly_flags"]}</td>
          <td class="hash">{row["sha256"]}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Report — {case_id}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:Arial,sans-serif;background:#f0f2f5;color:#222}}
  .header{{background:linear-gradient(135deg,#0b3d5c,#1a6b8a);color:white;padding:28px 40px}}
  .header h1{{font-size:24px;margin-bottom:6px}}
  .header p{{font-size:13px;opacity:.85}}
  .stats{{display:flex;gap:16px;padding:24px 40px;background:white;border-bottom:2px solid #e0e0e0}}
  .stat{{background:#f8f9fa;border-radius:10px;padding:16px 24px;text-align:center;flex:1;border:1px solid #e0e0e0}}
  .stat .num{{font-size:32px;font-weight:bold;color:#0b3d5c}}
  .stat .lbl{{font-size:12px;color:#666;margin-top:4px}}
  .section{{padding:24px 40px}}
  .section h2{{font-size:16px;color:#0b3d5c;margin-bottom:16px;padding-bottom:8px;border-bottom:2px solid #0b3d5c}}
  table{{width:100%;border-collapse:collapse;font-size:12px;background:white;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08)}}
  th{{background:#0b3d5c;color:white;padding:11px 14px;text-align:left;font-size:12px}}
  td{{padding:10px 14px;border-bottom:1px solid #eee;vertical-align:top}}
  tr:hover td{{background:#f0f6ff}}
  .hash{{font-size:10px;word-break:break-all;color:#888;max-width:180px}}
  .tl-item{{display:flex;gap:16px;margin-bottom:16px;align-items:flex-start}}
  .tl-dot{{width:14px;height:14px;border-radius:50%;margin-top:4px;flex-shrink:0}}
  .tl-blue{{background:#2980b9}}.tl-orange{{background:#e67e22}}.tl-red{{background:#c0392b}}
  .tl-content{{background:white;border-radius:8px;padding:12px 16px;flex:1;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .tl-title{{font-weight:bold;font-size:14px;margin-bottom:4px}}
  .tl-meta{{font-size:12px;color:#666}}
  .tl-flag{{font-size:12px;color:#c0392b;margin-top:6px}}
  .tl-ok{{font-size:12px;color:#27ae60;margin-top:6px}}
  .footer{{text-align:center;padding:24px;font-size:11px;color:#aaa;background:white;margin-top:8px}}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 Digital Image Metadata Forensic Report</h1>
  <p>Case ID: <b>{case_id}</b> &nbsp;|&nbsp; Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &nbsp;|&nbsp; CET333 Advanced Digital Forensics — Elsewedy University of Technology</p>
</div>
<div class="stats">
  <div class="stat"><div class="num">{total}</div><div class="lbl">📁 Total Images</div></div>
  <div class="stat"><div class="num">{with_gps}</div><div class="lbl">📍 With GPS</div></div>
  <div class="stat"><div class="num">{anomalous}</div><div class="lbl">⚠️ Anomalies</div></div>
  <div class="stat"><div class="num">{clean}</div><div class="lbl">✅ Clean Files</div></div>
</div>
<div class="section">
  <h2>📅 Investigation Timeline</h2>
  {timeline_rows}
</div>
<div class="section">
  <h2>📊 Evidence Metadata Table</h2>
  <table>
    <tr>
      <th>File</th><th>Timestamp</th><th>Camera</th>
      <th>GPS Coordinates</th><th>Altitude</th><th>Anomaly Flags</th><th>SHA-256</th>
    </tr>
    {table_rows}
  </table>
</div>
<div class="footer">
  This report was generated automatically by the Digital Forensic Metadata Tool.<br>
  For official use only — CET333 Advanced Digital Forensics — Elsewedy University of Technology
</div>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Digital Image Metadata Extraction & Geolocation Analysis")
    parser.add_argument("--input",  required=True,    help="Folder with evidence images")
    parser.add_argument("--output", default="output", help="Output folder")
    parser.add_argument("--case",   default="CASE-001", help="Case ID")
    args = parser.parse_args()

    input_dir  = Path(args.input)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    supported = {".jpg",".jpeg",".tiff",".tif",".png"}
    files = sorted([p for p in input_dir.iterdir() if p.suffix.lower() in supported])

    if not files:
        print("[!] No supported image files found.")
        return

    print(f"[*] Found {len(files)} image(s). Starting analysis...\n")

    records, raw_meta = [], {}
    for f in files:
        print(f"[*] Analyzing: {f.name}")
        record, tags = extract_record(f)
        records.append(record)
        raw_meta[f.name] = tags
        gps = f"GPS: {record['gps_latitude']}, {record['gps_longitude']}" if record["gps_latitude"] else "GPS: Not found"
        print(f"    {gps}")
        print(f"    Flags: {record['anomaly_flags']}")

    df = pd.DataFrame(records)
    df = df.sort_values("timestamp", na_position="last").reset_index(drop=True)

    csv_path    = output_dir / "metadata_results.csv"
    json_path   = output_dir / "raw_metadata.json"
    report_path = output_dir / "forensic_report.html"
    map_path    = output_dir / "map.html"
    chain_path  = output_dir / "chain_of_custody.csv"

    df.to_csv(csv_path, index=False)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(raw_meta, f, indent=2)

    generate_report(df, str(report_path), args.case)
    map_result = build_map(df, str(map_path))

    with open(chain_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["evidence_id","file_name","format","file_size_kb","sha256","timestamp","gps","altitude","anomaly_flags","analyzed_at","analyst"])
        for i, row in df.iterrows():
            gps_str = f"{row['gps_latitude']},{row['gps_longitude']}" if row["gps_latitude"] else "N/A"
            w.writerow([
                f"EVD-{i+1:03d}", row["file_name"], row["format"], row["file_size_kb"],
                row["sha256"], row["timestamp"] or "Unknown",
                gps_str, row["gps_altitude"] or "N/A",
                row["anomaly_flags"], datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Forensic Tool v2.0"
            ])

    print(f"\n{'='*55}")
    print(f"[+] Analysis complete! {len(df)} file(s) processed.")
    print(f"[+] Report        : {report_path}")
    print(f"[+] Map + Timeline: {map_path}")
    print(f"[+] CSV           : {csv_path}")
    print(f"[+] JSON          : {json_path}")
    print(f"[+] Chain         : {chain_path}")
    if not map_result:
        print(f"[!] Map not generated — no GPS data found")
    print(f"{'='*55}")


if __name__ == "__main__":
    main()
