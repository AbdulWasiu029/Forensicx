from flask import Flask, render_template, request, redirect, url_for, flash
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import os
import hashlib
import mimetypes
import datetime
import math

app = Flask(__name__)
app.secret_key = "secret123"

# ---------------- GPS ----------------
def convert_to_degrees(value):
    d, m, s = value
    return float(d) + (float(m) / 60.0) + (float(s) / 3600.0)

def extract_gps_info(exif_data):
    gps_info = {}
    for key in exif_data.keys():
        if TAGS.get(key) == "GPSInfo":
            for t in exif_data[key]:
                gps_info[GPSTAGS.get(t, t)] = exif_data[key][t]

    if not gps_info:
        return None

    try:
        lat = convert_to_degrees(gps_info['GPSLatitude'])
        if gps_info['GPSLatitudeRef'] != "N":
            lat = -lat

        lon = convert_to_degrees(gps_info['GPSLongitude'])
        if gps_info['GPSLongitudeRef'] != "E":
            lon = -lon

        return (lat, lon)
    except:
        return None

# ---------------- EXIF ----------------
def extract_image_metadata(image_path):
    try:
        img = Image.open(image_path)
        exif_data = img.getexif()

        if not exif_data:
            return None, None

        exif_info = {}
        for tag_id in exif_data:
            tag = TAGS.get(tag_id, tag_id)
            exif_info[tag] = exif_data.get(tag_id)

        exif_info["Author"] = exif_info.get("Artist", "Not Available")
        exif_info["Software"] = exif_info.get("Software", "Not Available")

        gps = extract_gps_info(exif_data)
        return exif_info, gps

    except Exception as e:
        print("EXIF ERROR:", e)
        return None, None

# ---------------- HASH ----------------
def generate_hashes(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        return md5, sha256

# --------------- File Meta ---------------
def scan_file(file_path):

    metadata = {}

    # ---------- BASIC (ALL FILES) ----------
    metadata["File Name"] = os.path.basename(file_path)
    metadata["File Size (KB)"] = round(os.path.getsize(file_path) / 1024, 2)

    file_type, _ = mimetypes.guess_type(file_path)
    metadata["File Type"] = file_type if file_type else "Unknown"

    stat = os.stat(file_path)
    metadata["Created (System)"] = datetime.datetime.fromtimestamp(stat.st_ctime)
    metadata["Modified (System)"] = datetime.datetime.fromtimestamp(stat.st_mtime)
    metadata["Last Accessed (System)"] = datetime.datetime.fromtimestamp(stat.st_atime)

    # ---------- HASH ----------
    with open(file_path, "rb") as f:
        data = f.read()
        metadata["MD5"] = hashlib.md5(data).hexdigest()
        metadata["SHA256"] = hashlib.sha256(data).hexdigest()

    # ---------- TYPE DETECTION ----------
    ext = file_path.lower()

    # 🔵 DOCX
    if ext.endswith(".docx"):
        try:
            from docx import Document
            doc = Document(file_path)
            core = doc.core_properties

            metadata["Author"] = core.author
            metadata["Last Modified By"] = core.last_modified_by
            metadata["Created (Doc)"] = core.created
            metadata["Modified (Doc)"] = core.modified

        except:
            metadata["DOCX"] = "Metadata read error"

    # 🟡 PDF
    elif ext.endswith(".pdf"):
        try:
            from PyPDF2 import PdfReader

            reader = PdfReader(file_path)
            info = reader.metadata

            if info:
                for k, v in info.items():
                    metadata[f"PDF_{k}"] = str(v)
            else:
                metadata["PDF"] = "No metadata found"

        except Exception as e:
            metadata["PDF_ERROR"] = str(e)

    # 🔴 EXE
    elif ext.endswith(".exe"):
        metadata["Note"] = "Executable detected (basic scan only)"

    # ⚫ UNKNOWN
    else:
        metadata["Note"] = "No deep metadata available for this file type"

    return metadata
# ------- Real File Type Detector ---------
def detect_real_file_type(file_path):
    import zipfile

    signatures = {
        b'%PDF': 'PDF',
        b'\xFF\xD8\xFF': 'JPG',
        b'\x89PNG\r\n\x1a\n': 'PNG',
        b'MZ': 'EXE',
        b'PK\x03\x04': 'ZIP'
    }

    with open(file_path, 'rb') as f:
        header = f.read(8)
        f.seek(0)
        content = f.read(1024)  # read more for text detection

    # 🔥 STEP 1: signature check
    for sig, filetype in signatures.items():
        if header.startswith(sig):

            if filetype == "ZIP":
                try:
                    with zipfile.ZipFile(file_path, 'r') as z:
                        names = z.namelist()

                        if any("word/" in n for n in names):
                            return "DOCX"
                        elif any("xl/" in n for n in names):
                            return "XLSX"
                        elif any("ppt/" in n for n in names):
                            return "PPTX"
                        else:
                            return "ZIP"
                except:
                    return "ZIP"

            return filetype

    # 🔥 STEP 2: TEXT DETECTION (THIS WAS MISSING)
    try:
        content.decode('utf-8')
        return "TXT"
    except:
        pass

    return "Unknown"
# ----------- Entropy Analysis ------------
def calculate_entropy(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    if not data:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    entropy = 0.0
    length = len(data)

    for count in freq:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 2)

# -------- File Intergirity Check ---------
def compare_files(file1_path, file2_path):
    import hashlib

    def get_hash(path):
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()

        with open(path, 'rb') as f:
            while chunk := f.read(4096):
                md5.update(chunk)
                sha256.update(chunk)

        return md5.hexdigest(), sha256.hexdigest()

    md5_1, sha1 = get_hash(file1_path)
    md5_2, sha2 = get_hash(file2_path)

    result = {
        "md5_1": md5_1,
        "md5_2": md5_2,
        "sha1": sha1,
        "sha2": sha2,
        "match_md5": md5_1 == md5_2,
        "match_sha": sha1 == sha2
    }

    return result

# ---------------- PROCESS ----------------
try:
    import psutil
except:
    psutil = None

def get_processes():
    if not psutil:
        return [], []

    processes = []
    suspicious = []

    for p in psutil.process_iter(['pid', 'name']):
        try:
            # ✔ better CPU sampling
            cpu = p.cpu_percent(interval=0.3)
            mem = p.memory_percent()

            if p.info['name'] == "System Idle Process":
                continue

            # ✔ Disk (MB total I/O, still best possible)
            try:
                io = p.io_counters()
                disk = (io.read_bytes + io.write_bytes) / (1024 * 1024)
            except:
                disk = 0

            # ❌ REMOVE FAKE NETWORK (not per-process reliable)
            network = 0  # keep placeholder

            proc = {
                'pid': p.info['pid'],
                'name': p.info['name'],
                'cpu': round(cpu, 1),
                'memory': round(mem, 1),
                'disk': round(disk, 2),
                'network': network,
                'status': "Active" if cpu > 1 else "Idle"
            }

            processes.append(proc)

            # 🔴 BETTER suspicious logic
            reasons = []

            if cpu > 50:
                reasons.append("High CPU")

            if mem > 30:
                reasons.append("High Memory")

            if disk > 1000:
                reasons.append("Heavy Disk Usage")

            if any(x in proc['name'].lower() for x in ["temp", "unknown", "miner"]):
                reasons.append("Suspicious Name")

            if reasons:
                proc['reason'] = ", ".join(reasons)
                suspicious.append(proc)

        except:
            continue

    processes = sorted(processes, key=lambda x: x['cpu'], reverse=True)

    return processes, suspicious

def get_network_connections():
    import psutil

    connections = []
    suspicious = []

    for conn in psutil.net_connections(kind='inet'):
        try:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""

            process = "Unknown"
            if conn.pid:
                try:
                    process = psutil.Process(conn.pid).name()
                except:
                    process = "Access Denied"

            data = {
                "pid": conn.pid,
                "process": process,
                "local": laddr,
                "remote": raddr,
                "status": conn.status
            }

            connections.append(data)

            # 🔴 FIXED SUSPICIOUS LOGIC (NO MORE FALSE POSITIVES)
            reason = None

            # 1. Unknown process + external
            if process == "Unknown" and conn.raddr:
                reason = "Unknown process connected externally"

            # 2. Failed connection attempt
            elif conn.status == "SYN_SENT":
                reason = "Connection attempt (not completed)"

            # 3. External connection but not common apps
            elif conn.raddr:
                ip = conn.raddr.ip

                if not ip.startswith("127.") and not ip.startswith("192.168"):
                    if process.lower() not in [
                        "chrome.exe",
                        "opera.exe",
                        "msedge.exe",
                        "msedgewebview2.exe"
                    ]:
                        reason = "External connection (uncommon process)"

            if reason:
                data["reason"] = reason
                suspicious.append(data)

        except:
            continue

    return connections, suspicious

def get_forensic_registry():
    import winreg
    import re

    results = []

    # 🔴 CLEAN VALUE (Readable)
    def clean_registry_value(value):
        try:
            if isinstance(value, bytes):

                # try decode
                try:
                    text = value.decode('utf-16', errors='ignore')
                    text = text.replace('\x00', '')

                    # extract filename
                    match = re.search(r'([A-Za-z0-9_\-\. ]+\.(lnk|docx|pdf|zip|jpg|png|exe))', text)
                    if match:
                        return match.group(1)

                    # if too messy → mark binary
                    if sum(c.isprintable() for c in text) / (len(text)+1) < 0.6:
                        return "[Binary Data]"

                    return text.strip()

                except:
                    return "[Binary Data]"

            return str(value)

        except:
            return str(value)

    # 🔴 RAW VALUE (Original like registry)
    def raw_registry_value(value):
        try:
            if isinstance(value, bytes):
                return value.hex()[:100] + "..."   # short hex preview
            return str(value)
        except:
            return str(value)

    # 🔴 READ FUNCTION
    def read_key(root, path, label):
        try:
            key = winreg.OpenKey(root, path)
            i = 0

            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)

                    if name == "MRUListEx":
                        i += 1
                        continue

                    results.append({
                        "category": label,
                        "name": name,
                        "raw": raw_registry_value(value),        # 🔥 original
                        "clean": clean_registry_value(value)     # 🔥 readable
                    })

                    i += 1

                except OSError:
                    break

        except Exception as e:
            results.append({
                "category": label,
                "name": "ERROR",
                "raw": str(e),
                "clean": str(e)
            })

    # 🔴 KEYS
    read_key(winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows\CurrentVersion\Run",
             "Startup (HKCU)")

    read_key(winreg.HKEY_LOCAL_MACHINE,
             r"Software\Microsoft\Windows\CurrentVersion\Run",
             "Startup (HKLM)")

    read_key(winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
             "RunOnce (HKCU)")

    read_key(winreg.HKEY_LOCAL_MACHINE,
             r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
             "RunOnce (HKLM)")

    read_key(winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
             "System Info")

    read_key(winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
             "Installed Programs")

    read_key(winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
             "Recent Files")

    read_key(winreg.HKEY_LOCAL_MACHINE,
             r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
             "USB Devices")

    read_key(winreg.HKEY_LOCAL_MACHINE,
             r"SYSTEM\CurrentControlSet\Services",
             "Services")

    return results

# ---------------- ROUTES ----------------
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':

        if 'file' not in request.files:
            flash('No file uploaded')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)

        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        UPLOAD_FOLDER = os.path.join(BASE_DIR, "static")
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        filename = file.filename
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        file.save(file_path)

        ext = filename.lower()

        # ================= IMAGE =================
        if ext.endswith(('.jpg', '.jpeg', '.png')):
            exif_data, gps_data = extract_image_metadata(file_path)
            md5, sha256 = generate_hashes(file_path)

            suspicious = exif_data is None

            return render_template(
                'results.html',
                filename=filename,
                exif_data=exif_data,
                md5=md5,
                sha256=sha256,
                suspicious=suspicious,
                gps_data=gps_data
            )

        # ================= OTHER FILES =================
        else:
            metadata = scan_file(file_path)

            return render_template(
                'filemeta.html',
                metadata=metadata
            )

    return render_template('index.html')

@app.route('/system')
def system():
    processes, suspicious = get_processes()
    return render_template("system.html",
                           processes=processes,
                           suspicious=suspicious)

@app.route('/meta', methods=['GET', 'POST'])
def meta():

    if request.method == 'POST':

        if 'file' not in request.files:
            flash('No file uploaded')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)

        filename = file.filename
        ext = filename.lower()

        # ✅ VALIDATION HERE (correct place)
        if not ext.endswith(('.jpg', '.jpeg', '.png')):
            flash("Only image files (JPG, PNG) are allowed here")
            return redirect(request.url)

        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        UPLOAD_FOLDER = os.path.join(BASE_DIR, "static")
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        exif_data, gps_data = extract_image_metadata(file_path)
        md5, sha256 = generate_hashes(file_path)

        suspicious = exif_data is None

        return render_template(
            'results.html',
            filename=filename,
            exif_data=exif_data,
            md5=md5,
            sha256=sha256,
            suspicious=suspicious,
            gps_data=gps_data
        )

    return render_template("meta.html")

@app.route('/filemeta', methods=['GET', 'POST'])
def filemeta():
    if request.method == 'POST':

        if 'file' not in request.files:
            flash("No file uploaded")
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash("No file selected")
            return redirect(request.url)

        filename = file.filename
        ext = filename.lower()

        # ❌ BLOCK IMAGES HERE (correct place)
        if ext.endswith(('.jpg', '.jpeg', '.png')):
            flash("Images are not allowed in File Metadata Analyzer")
            return redirect(request.url)

        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        UPLOAD_FOLDER = os.path.join(BASE_DIR, "static")
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        metadata = scan_file(file_path)

        return render_template("filemeta.html", metadata=metadata)

    return render_template("filemeta.html")

@app.route('/detect', methods=['GET', 'POST'])
def detect():

    if request.method == 'POST':

        if 'file' not in request.files:
            flash("No file uploaded")
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash("No file selected")
            return redirect(request.url)

        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        UPLOAD_FOLDER = os.path.join(BASE_DIR, "static")
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        # 🔍 DETECT REAL TYPE
        real_type = detect_real_file_type(file_path)

        # 🔍 EXTENSION
        ext = os.path.splitext(file.filename)[1].lower()
        ext_clean = ext.replace(".", "").upper()

        # 🔥 FINAL CLEAN LOGIC
        warning = None

        if real_type == "Unknown":
            warning = "Unknown file signature - cannot verify file type"

        elif ext_clean != real_type:
            warning = f"Extension {ext} does not match detected type {real_type}"

        return render_template(
            "detect.html",
            filename=file.filename,
            real_type=real_type,
            extension=ext,
            warning=warning
        )

    return render_template("detect.html")

@app.route('/entropy', methods=['GET', 'POST'])
def entropy():

    if request.method == 'POST':

        if 'file' not in request.files:
            flash("No file uploaded")
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash("No file selected")
            return redirect(request.url)

        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        UPLOAD_FOLDER = os.path.join(BASE_DIR, "static")
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        # 🔍 Calculate Entropy
        entropy_value = calculate_entropy(file_path)

        # 🔥 Risk logic
        if entropy_value >= 7.5:
            risk = "High (Packed / Encrypted)"
        elif entropy_value >= 6:
            risk = "Suspicious"
        else:
            risk = "Safe"

        return render_template(
            "entropy.html",
            filename=file.filename,
            entropy=entropy_value,
            risk=risk
        )

    return render_template("entropy.html")

@app.route('/network')
def network():
    connections, suspicious = get_network_connections()
    return render_template(
        "network.html",
        connections=connections,
        suspicious=suspicious
    )

@app.route('/registry')
def registry():
    data = get_forensic_registry()
    return render_template("registry.html", data=data)

@app.route('/integrity', methods=['GET', 'POST'])
def integrity():
    if request.method == 'POST':

        if 'file1' not in request.files or 'file2' not in request.files:
            flash("Upload both files")
            return redirect(request.url)

        f1 = request.files['file1']
        f2 = request.files['file2']

        if f1.filename == '' or f2.filename == '':
            flash("Select both files")
            return redirect(request.url)

        import os
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        UPLOAD_FOLDER = os.path.join(BASE_DIR, "static")
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        path1 = os.path.join(UPLOAD_FOLDER, f1.filename)
        path2 = os.path.join(UPLOAD_FOLDER, f2.filename)

        f1.save(path1)
        f2.save(path2)

        result = compare_files(path1, path2)

        return render_template("integrity.html", result=result)

    return render_template("integrity.html")

# ---------------- MAIN ----------------
if __name__ == '__main__':
    app.run(debug=True)