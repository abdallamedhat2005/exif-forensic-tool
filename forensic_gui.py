#!/usr/bin/env python3
"""
Forensic Tool GUI - CET333 Advanced Digital Forensics
Elsewedy University of Technology | Dr. Ayman Taha
"""

import sys
import os
import csv
import json
import hashlib
from datetime import datetime
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QTableWidget, QTableWidgetItem,
    QProgressBar, QTextEdit, QTabWidget, QHeaderView, QFrame,
    QStatusBar, QMessageBox, QGroupBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor

import exifread
import pandas as pd
from PIL import Image
import folium
from folium.plugins import MarkerCluster


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
        if len(parts) != 3:
            return None
        dec = parse_ratio(parts[0]) + parse_ratio(parts[1])/60 + parse_ratio(parts[2])/3600
        if str(ref_tag).strip() in ["S", "W"]:
            dec = -dec
        return round(dec, 7)
    except Exception:
        return None


def extract_record(image_path):
    path_str = str(image_path)
    file_hash = sha256_file(path_str)
    file_size = os.path.getsize(path_str)
    tags = {}
    anomalies = []
    try:
        with Image.open(path_str) as im:
            fmt = im.format
    except Exception:
        fmt = "UNKNOWN"
    if fmt == "PNG":
        anomalies.append("PNG format - EXIF/GPS rarely present")
    else:
        try:
            with open(path_str, "rb") as f:
                raw = exifread.process_file(f, details=False)
            tags = {str(k): str(v) for k, v in raw.items()}
        except Exception as e:
            anomalies.append("EXIF read error: " + str(e))
    timestamp = tags.get("EXIF DateTimeOriginal") or tags.get("Image DateTime")
    make  = tags.get("Image Make")
    model = tags.get("Image Model")
    software = tags.get("Image Software")
    lat = dms_to_decimal(tags.get("GPS GPSLatitude"),  tags.get("GPS GPSLatitudeRef"))
    lon = dms_to_decimal(tags.get("GPS GPSLongitude"), tags.get("GPS GPSLongitudeRef"))
    if not tags:      anomalies.append("No EXIF metadata - possible intentional stripping")
    if not timestamp: anomalies.append("Missing original timestamp")
    if lat is None or lon is None: anomalies.append("Missing GPS coordinates")
    if software:      anomalies.append("Software tag: " + str(software) + " - possible post-processing")
    if make is None and model is None and tags: anomalies.append("No camera make/model - suspicious")
    return {
        "file_name":     os.path.basename(path_str),
        "file_size_kb":  round(file_size / 1024, 1),
        "format":        fmt,
        "sha256":        file_hash,
        "timestamp":     timestamp or "N/A",
        "camera_make":   make or "Unknown",
        "camera_model":  model or "Unknown",
        "software":      software or "None",
        "gps_latitude":  lat,
        "gps_longitude": lon,
        "has_exif":      bool(tags),
        "anomaly_flags": " | ".join(anomalies) if anomalies else "None",
        "anomaly_count": len(anomalies),
    }


class AnalysisWorker(QThread):
    progress     = pyqtSignal(int)
    log          = pyqtSignal(str)
    result_ready = pyqtSignal(list)
    finished     = pyqtSignal(str)

    def __init__(self, input_dir, output_dir):
        super().__init__()
        self.input_dir  = input_dir
        self.output_dir = output_dir

    def run(self):
        exts = {".jpg", ".jpeg", ".tiff", ".tif", ".png"}
        images = [p for p in Path(self.input_dir).iterdir() if p.suffix.lower() in exts]
        if not images:
            self.log.emit("[!] No images found.")
            self.finished.emit("")
            return
        self.log.emit("[*] Found " + str(len(images)) + " image(s). Starting analysis...")
        os.makedirs(self.output_dir, exist_ok=True)
        records = []
        for i, img in enumerate(images, 1):
            self.log.emit("[*] Analyzing: " + img.name)
            rec = extract_record(img)
            records.append(rec)
            gps_str = str(rec["gps_latitude"]) + ", " + str(rec["gps_longitude"]) if rec["gps_latitude"] else "Not found"
            self.log.emit("    GPS: " + gps_str)
            self.log.emit("    Flags: " + rec["anomaly_flags"])
            self.progress.emit(int(i / len(images) * 70))

        pd.DataFrame(records).to_csv(os.path.join(self.output_dir, "metadata_results.csv"), index=False)

        coc_path = os.path.join(self.output_dir, "chain_of_custody.csv")
        with open(coc_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["evidence_id","file_name","sha256","timestamp","gps","anomaly_flags","analyzed_at","analyst"])
            for j, r in enumerate(records, 1):
                gps = str(r["gps_latitude"]) + "," + str(r["gps_longitude"]) if r["gps_latitude"] else "N/A"
                w.writerow(["EVD-"+str(j).zfill(3), r["file_name"], r["sha256"],
                            r["timestamp"], gps, r["anomaly_flags"],
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Forensic Tool GUI v2.0"])

        with open(os.path.join(self.output_dir, "raw_metadata.json"), "w") as f:
            json.dump(records, f, indent=2, default=str)

        self._write_html_report(records, os.path.join(self.output_dir, "forensic_report.html"))
        self.progress.emit(85)
        self._build_map(records, os.path.join(self.output_dir, "map.html"))
        self.progress.emit(100)

        self.log.emit("=" * 50)
        self.log.emit("[+] Done! " + str(len(records)) + " file(s) processed.")
        self.log.emit("[+] Output: " + self.output_dir)
        self.log.emit("=" * 50)
        self.result_ready.emit(records)
        self.finished.emit(self.output_dir)

    def _build_map(self, records, map_path):
        geo = [r for r in records if r["gps_latitude"] is not None]
        if not geo:
            self.log.emit("[!] No GPS data - map not generated.")
            return
        center = [
            sum(r["gps_latitude"] for r in geo) / len(geo),
            sum(r["gps_longitude"] for r in geo) / len(geo)
        ]
        m = folium.Map(location=center, zoom_start=12, tiles="OpenStreetMap")
        cluster = MarkerCluster(name="All Evidence").add_to(m)
        for r in geo:
            color = "red" if r["anomaly_count"] > 1 else "orange" if r["anomaly_count"] == 1 else "blue"
            status = "<b style='color:#c0392b'>" + r["anomaly_flags"] + "</b>" if r["anomaly_flags"] != "None" else "<b style='color:#27ae60'>No anomalies</b>"
            popup_html = (
                "<div style='font-family:Arial;min-width:200px;font-size:13px'>"
                "<b>" + r["file_name"] + "</b><br>"
                "Time: " + str(r["timestamp"]) + "<br>"
                "Camera: " + str(r["camera_make"]) + " " + str(r["camera_model"]) + "<br>"
                "GPS: " + str(r["gps_latitude"]) + ", " + str(r["gps_longitude"]) + "<br>"
                + status +
                "</div>"
            )
            folium.Marker(
                location=[r["gps_latitude"], r["gps_longitude"]],
                popup=folium.Popup(popup_html, max_width=300),
                tooltip=r["file_name"] + " | " + str(r["timestamp"]),
                icon=folium.Icon(color=color, icon="camera", prefix="fa")
            ).add_to(cluster)

        sorted_geo = sorted([r for r in geo if r["timestamp"] != "N/A"], key=lambda x: x["timestamp"])
        if len(sorted_geo) >= 2:
            coords = [[r["gps_latitude"], r["gps_longitude"]] for r in sorted_geo]
            folium.PolyLine(coords, color="#e74c3c", weight=3, dash_array="8", tooltip="Timeline Path").add_to(m)
            tl = folium.FeatureGroup(name="Timeline Order").add_to(m)
            for idx, r in enumerate(sorted_geo, 1):
                div = '<div style="background:#e74c3c;color:white;border-radius:50%;width:24px;height:24px;line-height:24px;text-align:center;font-weight:bold;font-size:12px;border:2px solid white">' + str(idx) + '</div>'
                folium.Marker(
                    location=[r["gps_latitude"], r["gps_longitude"]],
                    tooltip="#" + str(idx) + " - " + r["file_name"],
                    icon=folium.DivIcon(html=div, icon_size=(24, 24), icon_anchor=(12, 12))
                ).add_to(tl)

        folium.LayerControl(collapsed=False).add_to(m)
        m.save(map_path)
        self.log.emit("[+] Map saved: " + map_path)

    def _write_html_report(self, records, path):
        rows = ""
        for i, r in enumerate(records, 1):
            bg = "#fff0f0" if r["anomaly_count"] > 0 else "#f0fff4"
            fc = "#dc2626" if r["anomaly_count"] > 0 else "#16a34a"
            gps = str(r["gps_latitude"]) + ", " + str(r["gps_longitude"]) if r["gps_latitude"] else "N/A"
            rows += "<tr style='background:" + bg + "'><td>EVD-" + str(i).zfill(3) + "</td><td>" + r["file_name"] + "</td><td>" + str(r["timestamp"]) + "</td><td>" + str(r["camera_make"]) + " " + str(r["camera_model"]) + "</td><td>" + gps + "</td><td style='color:" + fc + ";font-weight:600'>" + r["anomaly_flags"] + "</td><td style='font-family:monospace;font-size:10px'>" + r["sha256"][:32] + "...</td></tr>"
        html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Forensic Report</title><style>body{font-family:Arial;background:#f8fafc;padding:20px}.header{background:linear-gradient(135deg,#0f172a,#1e3a5f);color:white;padding:30px;border-radius:12px;margin-bottom:24px}table{width:100%;border-collapse:collapse;background:white;border-radius:12px;overflow:hidden}th{background:#0f172a;color:white;padding:12px;text-align:left;font-size:12px}td{padding:11px;font-size:13px;border-bottom:1px solid #f1f5f9}</style></head><body><div class='header'><h1>Digital Forensic Report</h1><p>CET333 - Advanced Digital Forensics | Spring 2026 | Dr. Ayman Taha | Elsewedy University</p><p>Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " | Total: " + str(len(records)) + " file(s)</p></div><table><thead><tr><th>ID</th><th>File</th><th>Timestamp</th><th>Camera</th><th>GPS</th><th>Anomaly Flags</th><th>SHA-256</th></tr></thead><tbody>" + rows + "</tbody></table></body></html>"
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)


class ForensicGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Digital Forensic Tool v2.0 - CET333")
        self.setMinimumSize(1000, 680)
        self.input_dir  = ""
        self.output_dir = ""
        self._build_ui()
        self._apply_dark_theme()

    def _apply_dark_theme(self):
        self.setStyleSheet(
            "QMainWindow, QWidget { background-color: #0f172a; color: #e2e8f0; font-family: Segoe UI, Arial; }"
            "QGroupBox { border: 1px solid #334155; border-radius: 8px; margin-top: 8px; padding-top: 8px; font-weight: 600; color: #94a3b8; }"
            "QGroupBox::title { subcontrol-origin: margin; padding: 0 6px; }"
            "QPushButton { background: #1e40af; color: white; border: none; border-radius: 6px; padding: 8px 18px; font-weight: 600; font-size: 13px; }"
            "QPushButton:hover { background: #2563eb; }"
            "QPushButton:disabled { background: #334155; color: #64748b; }"
            "QPushButton#btn_open { background: #0f766e; }"
            "QPushButton#btn_open:hover { background: #0d9488; }"
            "QPushButton#btn_report { background: #7c3aed; }"
            "QPushButton#btn_report:hover { background: #8b5cf6; }"
            "QLabel { color: #cbd5e1; }"
            "QLabel#lbl_title { color: #38bdf8; font-size: 20px; font-weight: 700; }"
            "QLabel#lbl_sub { color: #64748b; font-size: 12px; }"
            "QTextEdit { background: #1e293b; border: 1px solid #334155; border-radius: 6px; color: #e2e8f0; padding: 6px; font-family: Consolas, monospace; font-size: 12px; }"
            "QProgressBar { background: #1e293b; border: 1px solid #334155; border-radius: 6px; height: 14px; text-align: center; color: white; font-size: 11px; }"
            "QProgressBar::chunk { background: #0ea5e9; border-radius: 5px; }"
            "QTableWidget { background: #1e293b; border: 1px solid #334155; border-radius: 6px; gridline-color: #334155; font-size: 12px; }"
            "QTableWidget::item { padding: 6px; color: #cbd5e1; }"
            "QTableWidget::item:selected { background: #1e40af; }"
            "QHeaderView::section { background: #0f172a; color: #94a3b8; padding: 8px; border: none; border-bottom: 1px solid #334155; font-weight: 600; font-size: 11px; }"
            "QTabWidget::pane { border: 1px solid #334155; border-radius: 6px; }"
            "QTabBar::tab { background: #1e293b; color: #94a3b8; padding: 8px 18px; border-radius: 6px 6px 0 0; margin-right: 2px; }"
            "QTabBar::tab:selected { background: #1e40af; color: white; }"
            "QStatusBar { background: #0f172a; color: #64748b; font-size: 11px; border-top: 1px solid #334155; }"
        )

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(16, 16, 16, 8)
        main_layout.setSpacing(12)

        header = QFrame()
        header.setStyleSheet("background:#1e293b;border-radius:10px;")
        h_lay = QHBoxLayout(header)
        h_lay.setContentsMargins(16, 10, 16, 10)
        title_col = QVBoxLayout()
        lbl_title = QLabel("Digital Forensic Tool v2.0")
        lbl_title.setObjectName("lbl_title")
        lbl_sub = QLabel("CET333 - Advanced Digital Forensics  |  Elsewedy University  |  Dr. Ayman Taha")
        lbl_sub.setObjectName("lbl_sub")
        title_col.addWidget(lbl_title)
        title_col.addWidget(lbl_sub)
        h_lay.addLayout(title_col)
        h_lay.addStretch()
        main_layout.addWidget(header)

        ctrl = QGroupBox("Evidence Setup")
        ctrl_lay = QHBoxLayout(ctrl)
        self.lbl_input = QLabel("No input folder selected")
        btn_input = QPushButton("Select Evidence Folder")
        btn_input.setObjectName("btn_open")
        btn_input.clicked.connect(self._pick_input)
        self.lbl_output = QLabel("No output folder selected")
        btn_output = QPushButton("Select Output Folder")
        btn_output.clicked.connect(self._pick_output)
        self.btn_run = QPushButton("Run Analysis")
        self.btn_run.setEnabled(False)
        self.btn_run.clicked.connect(self._run_analysis)
        self.btn_run.setMinimumWidth(140)
        ctrl_lay.addWidget(btn_input)
        ctrl_lay.addWidget(self.lbl_input, 1)
        ctrl_lay.addWidget(btn_output)
        ctrl_lay.addWidget(self.lbl_output, 1)
        ctrl_lay.addWidget(self.btn_run)
        main_layout.addWidget(ctrl)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        main_layout.addWidget(self.progress)

        tabs = QTabWidget()
        tab_table = QWidget()
        tbl_lay = QVBoxLayout(tab_table)
        tbl_lay.setContentsMargins(0, 8, 0, 0)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Evidence ID","File Name","Timestamp","Camera","GPS Coordinates","Anomaly Flags","SHA-256"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.verticalHeader().setVisible(False)
        tbl_lay.addWidget(self.table)
        tabs.addTab(tab_table, "Results Table")

        tab_log = QWidget()
        log_lay = QVBoxLayout(tab_log)
        log_lay.setContentsMargins(0, 8, 0, 0)
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        log_lay.addWidget(self.log_box)
        tabs.addTab(tab_log, "Analysis Log")
        main_layout.addWidget(tabs)

        bot = QHBoxLayout()
        self.btn_report = QPushButton("Open HTML Report")
        self.btn_report.setObjectName("btn_report")
        self.btn_report.setEnabled(False)
        self.btn_report.clicked.connect(self._open_report)
        self.btn_map = QPushButton("Open Map")
        self.btn_map.setEnabled(False)
        self.btn_map.clicked.connect(self._open_map)
        self.btn_csv = QPushButton("Open CSV")
        self.btn_csv.setEnabled(False)
        self.btn_csv.clicked.connect(self._open_csv)
        btn_clear = QPushButton("Clear")
        btn_clear.clicked.connect(self._clear)
        bot.addWidget(self.btn_report)
        bot.addWidget(self.btn_map)
        bot.addWidget(self.btn_csv)
        bot.addStretch()
        bot.addWidget(btn_clear)
        main_layout.addLayout(bot)

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Ready - Select evidence folder to begin.")

    def _pick_input(self):
        d = QFileDialog.getExistingDirectory(self, "Select Evidence Folder")
        if d:
            self.input_dir = d
            count = sum(1 for f in Path(d).iterdir() if f.suffix.lower() in {".jpg",".jpeg",".tiff",".tif",".png"})
            self.lbl_input.setText(d + "  (" + str(count) + " image(s))")
            if not self.output_dir:
                self.output_dir = os.path.join(d, "output")
                self.lbl_output.setText(self.output_dir + " (auto)")
            self._check_ready()

    def _pick_output(self):
        d = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if d:
            self.output_dir = d
            self.lbl_output.setText(d)
            self._check_ready()

    def _check_ready(self):
        self.btn_run.setEnabled(bool(self.input_dir and self.output_dir))

    def _run_analysis(self):
        self.btn_run.setEnabled(False)
        self.progress.setValue(0)
        self.table.setRowCount(0)
        self.log_box.clear()
        self.status.showMessage("Analyzing...")
        self.worker = AnalysisWorker(self.input_dir, self.output_dir)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.log.connect(self.log_box.append)
        self.worker.result_ready.connect(self._populate_table)
        self.worker.finished.connect(self._on_done)
        self.worker.start()

    def _populate_table(self, records):
        self.table.setRowCount(len(records))
        for i, r in enumerate(records):
            gps = str(r["gps_latitude"]) + ", " + str(r["gps_longitude"]) if r["gps_latitude"] else "Not found"
            items = ["EVD-"+str(i+1).zfill(3), r["file_name"], r["timestamp"],
                     str(r["camera_make"])+" "+str(r["camera_model"]), gps, r["anomaly_flags"], r["sha256"][:32]+"..."]
            for j, val in enumerate(items):
                item = QTableWidgetItem(str(val))
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                if j == 5 and r["anomaly_count"] > 0:
                    item.setForeground(QColor("#f87171"))
                elif j == 5:
                    item.setForeground(QColor("#4ade80"))
                self.table.setItem(i, j, item)

    def _on_done(self, out_dir):
        self.btn_run.setEnabled(True)
        if out_dir:
            self.btn_report.setEnabled(True)
            self.btn_map.setEnabled(True)
            self.btn_csv.setEnabled(True)
            self.status.showMessage("Analysis complete! Output: " + out_dir)
        else:
            self.status.showMessage("No images found.")

    def _open_report(self):
        p = os.path.join(self.output_dir, "forensic_report.html")
        if os.path.exists(p): os.startfile(p)

    def _open_map(self):
        p = os.path.join(self.output_dir, "map.html")
        if os.path.exists(p):
            os.startfile(p)
        else:
            QMessageBox.information(self, "Map", "No GPS data found - map was not generated.")

    def _open_csv(self):
        p = os.path.join(self.output_dir, "metadata_results.csv")
        if os.path.exists(p): os.startfile(p)

    def _clear(self):
        self.table.setRowCount(0)
        self.log_box.clear()
        self.progress.setValue(0)
        self.status.showMessage("Cleared.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ForensicGUI()
    window.show()
    sys.exit(app.exec_())
