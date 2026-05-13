# Digital Image Metadata Extraction & Geolocation Analysis
### CET333 - Advanced Digital Forensics | Spring 2026

A professional forensic tool for extracting EXIF metadata from images,
decoding GPS coordinates, visualizing locations on an interactive map,
detecting metadata anomalies, and generating forensic-grade reports.

## Features
- EXIF metadata extraction (JPG, JPEG, TIFF, PNG)
- GPS coordinate decoding & interactive map
- Timeline visualization (multiple images sorted by time)
- Metadata anomaly detection (manipulation signs)
- Forensic HTML report with chain of custody
- SHA-256 hash for every evidence file

## Setup
```
pip install -r requirements.txt
```

## Usage
```
python forensic_tool.py --input evidence/ --output output/
```

## Output Files
| File | Description |
|------|-------------|
| output/forensic_report.html | Full forensic report |
| output/map.html | Interactive GPS map |
| output/metadata_results.csv | Metadata table |
| output/chain_of_custody.csv | Evidence log with hashes |
| output/raw_metadata.json | Raw EXIF data |

## Team
- Student 1: Abdalla medhat
- Student 2: Mahmoud ibrahim
- Student 3: Omar osama 

## Instructor
Dr. Ayman Taha - Elsewedy University of Technology
