import logging
import sys
import os
import subprocess
import re
import argparse
from datetime import datetime, time, date
from time import sleep
import shutil
from pathlib import Path
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import random
import sqlite3
import json

from r2_key_extractor import (
    extract_private_keys,
    validate_key_with_openssl
)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
}

# python3 android_apk_downloader.py --start-date "2026-10-04" --end-date "2026-10-04" --find-apks
# python3 android_apk_downloader.py --start-date "2026-10-04" --end-date "2026-10-04" --find-apks --download-apks
# python3 android_apk_downloader.py --start-date "2026-10-04" --end-date "2026-10-04" --find-apks --download-apks --analyze-apks
# python3 android_apk_downloader.py --search-findings        <--  this shows all results in the sqlite db
# python3 android_apk_downloader.py --search-findings "GLIA" <-- this filters results to only those which contain the provided string

def check_security_txt(website):
    "determine if the target organization has a VDP or bug bounty program"
    security_program = ""
    security_program_details = ""

    # Ensure the URL has a scheme to prevent requests module errors
    if not website.startswith(('http://', 'https://')):
        website = 'https://' + website

        # Safely construct the URL
        target_url = website.rstrip('/') + '/.well-known/security.txt'

        try:
            sleep(0.05)
            # Use a timeout to prevent hanging on unresponsive servers
            print(f"requesting: {target_url}")
            response = requests.get(target_url, headers=HEADERS, timeout=15, allow_redirects=True)
            content_type = response.headers.get('Content-Type', '').lower()

            # Apply the user's specific failure conditions
            if response.status_code == 404 or 'text/plain' not in content_type:
                security_program = 'No'
                security_program_details = 'None'
            else:
                # If it is a 200 OK and text/plain, mark it as Yes
                program_details = response.text.replace('\r\n', '\n')
                security_program = 'Yes' if response.status_code == 200 else 'No'
                security_program_details = program_details if response.status_code == 200 else 'None'

        except requests.RequestException:
            # Catch DNS failures, timeouts, and connection errors
            security_program = 'No'
            security_program_details = 'None'
    return security_program, security_program_details

def get_apk_info(pkg_name):
    # get all apk info from the appstore listing
    url = f"https://play.google.com/store/apps/details?id={pkg_name}&hl=en_US"
    try:
        # Pass headers to avoid blocks
        response = requests.get(url, headers=HEADERS, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")

        org_name = ""
        org_website = ""
        appstore_url = url

        # 1. NEW LOGIC: Extract org_name from the developer link by default
        # Search the entire page for the developer URL pattern
        dev_link = soup.find('a', href=re.compile(r'/store/apps/developer\?id='))
        if dev_link:
            # Example href: "/store/apps/developer?id=The+Capitol+Employees+Credit+Union"
            extracted_id = dev_link['href'].split('=')[-1]
            # Replace the '+' symbols with spaces
            org_name = extracted_id.replace('+', ' ')

        # 2. Proceed with the rest of the extraction in the contacts block
        target_div = soup.find("div", id="developer-contacts")

        if target_div:
            org_website = None
            developer_info_container = None
            GENERIC_DOMAINS = {'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com'}

            # We still find the "About the developer" section to enable the email fallback
            developer_heading_text = target_div.find(string=re.compile(r'^\s*About the developer\s*$'))

            if developer_heading_text:
                heading_div = developer_heading_text.parent
                developer_info_container = heading_div.find_next_sibling()

                # FALLBACK FOR NAME: If the dev link didn't exist, try the old method
                if not org_name and developer_info_container:
                    name_div = developer_info_container.find('div')
                    if name_div:
                        org_name = name_div.text.strip()

            # 3. Try to get the Website URL from the "Website" button
            website_text_node = target_div.find(string=re.compile(r'^\s*Website\s*$'))

            if website_text_node:
                parent_link = website_text_node.find_parent('a')
                if parent_link and 'href' in parent_link.attrs:
                    full_url = parent_link['href']
                    parsed_url = urlparse(full_url)
                    org_website = parsed_url.netloc.replace('www.', '')

            # 4. FALLBACK FOR WEBSITE: Extract the domain from the developer's email
            if not org_website and developer_info_container:
                email_node = developer_info_container.find(string=re.compile(r'@'))

                if email_node:
                    email_address = email_node.strip()
                    if '@' in email_address:
                        extracted_domain = email_address.split('@')[-1].lower()
                        if extracted_domain not in GENERIC_DOMAINS:
                            org_website = "https://" + extracted_domain

        else:
            print(f"The specified div ID was not found for {pkg_name}.")

    except Exception as e:
        print(f"Error enriching info for {pkg_name}: {e}")

    return org_name, org_website, appstore_url

def prune_false_positives(file_path: str):
    "prune false positives from the specified file"
    false_pos_lst = [
        r'.+\[generic apiKey\] apiKey": ""$\n',
        r'.+\[generic apiKey\] apiKey": "",$\n',
        r'.+\[generic api_key\] api_key": ""$\n',
        r'.+\[generic api_key\] api_key": "",$\n',
        r'.+\[generic api_key\] api_key" />$\n',
        r'.+\[generic api_key\] API_KEY" android:value=""/>$\n',
        r'.+\[generic api_key\] API_KEY:Ljava/lang/String; = ""$\n',
        r'.+\[generic apiKey\] ApiKey" />$\n',

        r'.+\[generic secret\] secret": ""$\n',
        r'.+\[generic secret\] secret": "",$\n',
        r'.+\[generic secret\] Secret": ""$\n',
        r'.+\[generic secret\] Secret": "",$\n',
        r'.+\[generic secret\] Secret:$\n',
        r'.+\[generic secret\] SECRET:Ljava/lang/String; = ""$\n',

        r'.+\[generic storageBucket\] storageBucket$\n',
        r'.+\[generic storageBucket\] StorageBucket$\n',

        r'.+serviceCredentialEnabled": false$\n',
        r'.+\[GLIA ABEAI Enabled\] abeaiEnabled.+true[,]$\n',
        r'.+\[GLIA ABEAI Enabled\] abeaiEnabled.+true$\n',
        r'.+\[GLIA API Key ID\] gliaApiKeyId": "",$\n',
        r'.+\[GLIA Queue ID\] gliaQueueId": "",$\n',
        r'.+\[GLIA Options\] gliaOptions": \{$\n',
        r'.+\[GLIA Direct ID Enabled\] directIdEnabled": false,$\n',
        r'.+\[GLIA Site ID\] gliaSiteId": "",$\n',
        r'.+\[GLIA API Key Secret\] gliaApiKeySecret": "",$\n',

        r'.+\[GLIA Site ID\] gliaSiteId$\n',
        r'.+\[GLIA Options\] GliaOptionsModel.fromJson$\n',
        r'.+\[GLIA Options\] GliaOptionsModelToJson@\d+$\n',
        r'.+\[GLIA Options\] GliaOptionsModel$\n',
        r'.+\[GLIA Options\] gliaOptions$\n',
        r'.+\[GLIA ABEAI Enabled\] abeaiEnabled$\n',
        r'.+\[GLIA Direct ID Enabled\] directIdEnabled$\n',
        r'.+\[GLIA Queue ID\] gliaQueueId$\n',
        r'.+\[GLIA API Key Secret\] gliaApiKeySecret$\n',
        r'.+\[GLIA Options\] GliaOptionsModelFromJson@\d+$\n',
        r'.+\[GLIA API Key ID\] gliaApiKeyId$\n',
        r'.+\[GLIA Service Credential Enabled] serviceCredentialEnabled$\n'
    ]

    compiled_patterns = [re.compile(p) for p in false_pos_lst]

    with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
        lines = fh.readlines()

    removed_lines = []
    result_lines = []

    with open(file_path, "w", encoding="utf-8", errors="ignore") as fh:
        for line in lines:
            # Check if any of the compiled patterns are found in the line
            if not any(pattern.search(line) for pattern in compiled_patterns):
                fh.write(line)
                result_lines.append(line)
            else:
                removed_lines.append(line)

    for l in removed_lines:
        print(l)
    print(f"removed {len(removed_lines)} false positives!")

    return result_lines

def move_and_rename_if_exists(source_path: str, dest_dir: str):
    src = Path(source_path)
    dst_folder = Path(dest_dir)

    dst_folder.mkdir(parents=True, exist_ok=True)

    dst = dst_folder / src.name

    counter = 1
    while dst.exists():
        new_name = f"{src.stem}_{counter}{src.suffix}"
        dst = dst_folder / new_name
        counter += 1

    # Move and rename the file
    src.rename(dst)
    #print(f"Moved to: {dst}")

def get_installed_packages_in_range(start_date, end_date):
    """Parses dumpsys package output to find apps installed within the timeframe."""
    print("Fetching package list from device...")
    try:
        raw_output = subprocess.check_output(
            ["adb", "shell", "dumpsys", "-t 90", "package"]
        ).decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError as e:
        print(f"Failed to query device: {e}")
        return []

    matching_packages = []
    current_package = None

    for line in raw_output.splitlines():
        line = line.strip()

        if line.startswith("Package ["):
            current_package = line.split("[")[1].split("]")[0]

        elif "firstInstallTime=" in line and current_package:
            date_str = line.split("firstInstallTime=")[1].strip()[:19]
            try:
                install_time = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                if start_date <= install_time <= end_date:
                    matching_packages.append((current_package, install_time))
            except ValueError:
                continue

    return matching_packages

def download_apks_for_package(package_name):
    """Creates directory and pulls all base and split APKs for the target package."""
    # Create target local directory named after the package
    os.makedirs(package_name, exist_ok=True)

    base_pkg_path = Path(f"{package_name}/base.apk")

    if base_pkg_path.is_file():
        print(f"skipping! package already exists: {str(base_pkg_path)}")
        return False

    try:
        # Get all APK paths associated with the package (handles split APKs)
        path_output = subprocess.check_output(
            ["adb", "shell", "pm", "path", package_name]
        ).decode("utf-8", errors="ignore")

        apk_paths = [
            line.strip().replace("package:", "")
            for line in path_output.splitlines()
            if line.strip().startswith("package:")
        ]

        if not apk_paths:
            print(f"  No APK paths found for {package_name}.")
            return

        print(f"  Found {len(apk_paths)} APK path(s). Pulling...")

        for remote_apk_path in apk_paths:
            # Pull APK into target folder
            subprocess.run(
                ["adb", "pull", remote_apk_path, package_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=True,
            )
            filename = os.path.basename(remote_apk_path)
            print(f"   -> Saved: {package_name}/{filename}")

    except subprocess.CalledProcessError as e:
        print(f"  Error pulling APKs for {package_name}: {e}")

    return

def static_analysis(package_name):
    apk_names = [f for f in os.listdir(package_name) if f.endswith(".apk")]
    print(f"processing: {', '.join(apk_names)}")
    all_match_lst = set()
    for p in apk_names:
        #os.makedirs(package_name+"/decompiled/"+p, exist_ok=True)
        try:
            print(f"starting static analysis on: {p}")

            cmd_result = subprocess.check_output(
                ["apktool", "d", "-q", f"{package_name}/{p}", "-o", f"{package_name}/decompiled/{p}"]
            ).decode("utf-8", errors="ignore")

            # plaintext secrets in directories
            dirs_lst = [
                Path(f"{package_name}/decompiled/{p}/res/raw/"),
                Path(f"{package_name}/decompiled/{p}/res/values/"),
                Path(f"{package_name}/decompiled/{p}/assets/"),
            ]

            # scan res/raw/ and assets/ directories for .pem .p12 .jks .crt .db .sqlite and move files to parent package directory
            for d in dirs_lst:
                files = d.rglob("*.pem")
                for file_path in files:
                    if file_path.is_file():
                        dest_path = Path(f"{package_name}") / file_path.name
                        shutil.move(file_path, dest_path)
                        print(f"Moved: {file_path.name} -> {dest_path}")
                files = d.rglob("*.p12")
                for file_path in files:
                    if file_path.is_file():
                        dest_path = Path(f"{package_name}") / file_path.name
                        shutil.move(file_path, dest_path)
                        print(f"Moved: {file_path.name} -> {dest_path}")
                files = d.rglob("*.jks")
                for file_path in files:
                    if file_path.is_file():
                        dest_path = Path(f"{package_name}") / file_path.name
                        shutil.move(file_path, dest_path)
                        print(f"Moved: {file_path.name} -> {dest_path}")
                files = d.rglob("*.crt")
                for file_path in files:
                    if file_path.is_file():
                        dest_path = Path(f"{package_name}") / file_path.name
                        shutil.move(file_path, dest_path)
                        print(f"Moved: {file_path.name} -> {dest_path}")
                files = d.rglob("*.db")
                for file_path in files:
                    if file_path.is_file():
                        dest_path = Path(f"{package_name}") / file_path.name
                        shutil.move(file_path, dest_path)
                        print(f"Moved: {file_path.name} -> {dest_path}")
                files = d.rglob("*.sqlite")
                for file_path in files:
                    if file_path.is_file():
                        dest_path = Path(f"{package_name}") / file_path.name
                        shutil.move(file_path, dest_path)
                        print(f"Moved: {file_path.name} -> {dest_path}")

            # recursive find .json .xml .env in dirs_lst files and append to files_lst
            # plaintext secrets in files
            files_lst = [
                Path(f"{package_name}/decompiled/{p}/AndroidManifest.xml")
            ]

            for d in dirs_lst:
                files_lst.extend(d.rglob("*.xml"))
                files_lst.extend(d.rglob("*.json"))
                files_lst.extend(d.rglob("*.env"))

            # extract strings from lib/*.so
            package_dir = Path(package_name)
            lib_files = list(Path(f"{package_name}/decompiled/{p}/lib/").rglob("*.so"))
            for f in lib_files:
                txt_file = package_dir / f"{p}#{f.parent.name}#{f.stem}#strings.txt"
                with open(str(txt_file), "w", encoding="utf-8", errors="ignore") as out_f:
                    subprocess.run(["strings", "-n 10", str(f)], stdout=out_f, check=True)
                files_lst.append(Path(txt_file))


            build_config_files = list(Path(f"{package_name}/decompiled/{p}/").rglob("BuildConfig.smali"))
            for f in build_config_files:
                files_lst.append(Path(f))

            bin_files_analyzed = set()
            for f in files_lst:
                has_matches = None
                match_lst = set()
                with open(f, "r", encoding="utf-8") as fh:

                   # review each interesting file for sensitive strings
                    sensitive_matchdict = {
                        "generic api_key": r"api_key[:'\"=].*",
                        "generic secret": r"secret[:'\"=].*",
                        "generic apiKey": r"apiKey[:'\"=].*",
                        "generic storageBucket": r"storageBucket.*",

                        "GLIA Options": r"gliaOptions.*",
                        "GLIA Site ID": r"gliaSiteId.*",
                        "GLIA Queue ID": r"gliaQueueId.*",
                        "GLIA API Key ID": r"gliaApiKeyId.*",
                        "GLIA API Key Secret": r"gliaApiKeySecret.*",
                        "GLIA Site ID": r"gliaSiteId.*",
                        "GLIA Direct ID Enabled": r"directIdEnabled.*",
                        "GLIA ABEAI Enabled": r"abeaiEnabled.*",
                        "GLIA Service Credential Enabled": r"serviceCredentialEnabled.*",

                        "Airship URL": r"urbanairship\.com/api.*",
                        "Airship App Key": r"productionAppKey.*",
                        "Airship App Secret": r"productionAppSecret.*",

                        "Cloudinary": r"cloudinary://.*",
                        "Firebase URL": r".*firebaseio\.com",
                        "Slack Token": r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",

                        "RSA private key":       r"-----BEGIN RSA PRIVATE KEY-----",
                        "SSH (DSA) private key": r"-----BEGIN DSA PRIVATE KEY-----",
                        "SSH (EC) private key":  r"-----BEGIN EC PRIVATE KEY-----",
                        "PGP private key block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",

                        "Amazon AWS Access Key ID":        r"AWS_ACCESS_KEY_ID",
                        "Amazon AWS Secret Access Key":    r"AWS_SECRET_ACCESS_KEY",
                        "Amazon AWS S3 bucket":            r".+\.s3\..+\.amazonaws.com",
                        "Amazon AWS Access Key ID":        r"AKIA[0-9A-Z]{16}",
                        "Amazon MWS Auth Token":           r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                        "Amazon AWS Lambda URL":           r"[a-z0-9]{32}\.lambda-url\.[a-z0-9-]+(?:\.localhost)?\.on\.aws(?:/.*)?$",
                        "Amazon AWS Lambda Function Execute URL": r"(?P<api_id>[a-z0-9]+)\.execute-api\.(?P<region>[a-z0-9-]+)\.amazonaws\.com/(?P<stage>[^/]+)",

                        "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
                        "Facebook OAuth": r"[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
                        "GitHub": r"[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
                        "Generic API Key": r"[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
                        "Generic Secret": r"[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",

                        "Google Cloud Function URL": r"(?:(?P<region>[a-z0-9-]+)-(?P<project>[a-z0-9-:]+)\.cloudfunctions\.net\/(?P<func_legacy>[a-zA-Z0-9_-]+)|(?P<run_name>[a-z0-9-]+)-(?P<run_hash>[a-z0-9]+)-(?P<run_region>[a-z0-9-]+)\.a\.run\.app)$",
                        "Google API Key (Cloud Platform, Drive, Gmail, YouTube)":  r"AIza[0-9A-Za-z\-_]{35}",
                        "Google OAuth (Cloud Platform, Drive, Gmail, YouTube)":    r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
                        "Google (GCP) Service-account":                            r"\"type\": \"service_account\"",
                        "Google OAuth Access Token":                               r"ya29\.[0-9A-Za-z\-_]+",

                        "Heroku API Key": r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
                        "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
                        "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
                        "Password in URL": r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}[\"'\s]",
                        "PayPal Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
                        "Picatic API Key": r"sk_live_[0-9a-z]{32}",
                        "Slack Webhook": r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
                        "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
                        "Stripe Restricted API Key": r"rk_live_[0-9a-zA-Z]{24}",
                        "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
                        "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
                        "Twilio API Key": r"SK[0-9a-fA-F]{32}",
                        "Twitter Access Token": r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
                        "Twitter OAuth": r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]"
                    }

                    compiled_patterns = {
                        pname: re.compile(pattern, re.IGNORECASE)
                        for pname, pattern in sensitive_matchdict.items()
                    }

                    for line_number, line in enumerate(fh, start=1):
                        clean_line = line.rstrip("\n")

                        for pname, compiled_pattern in compiled_patterns.items():
                            matches = list(compiled_pattern.finditer(clean_line))

                            if matches:
                                has_matches = True
                                for match in matches:
                                    match_lst.add(f"[{pname}] {match.group(0)}")
                                    all_match_lst.add(f"[{pname}] {match.group(0)}")

                                    if 'private key' in pname:
                                        #print(f"DEBUG DEBUG DEBUG: found private key preamble in {f}")
                                        sf = str(f)
                                        app_name = sf.split("/")[0]
                                        apk_name = (sf.split("/")[1]).split("#")[0]
                                        so_name =  (sf.split("/")[1]).split("#")[1] + "/" + (sf.split("/")[1]).split("#")[2] + ".so"
                                        so_file = f"{app_name}/decompiled/{apk_name}/lib/{so_name}"
                                        so_basename = so_name.split("/")[1]
                                        #print(f"extracting private key from .so binary: {so_file}")
                                        #print(so_basename)
                                        shutil.copy(f"{so_file}", f"{package_name}/")

                                        if f"{so_file}" not in bin_files_analyzed:
                                            bin_files_analyzed.add(f"{so_file}")
                                        else:
                                            print(f"skipping {so_basename} (already analyzed)")
                                            continue

                                        private_key_search_lst = [
                                            'DSA private key',
                                            'SSH (DSA) private key',
                                            'RSA private key',
                                            'SSH (RSA) private key',
                                            'EC private key',
                                            'SSH (EC) private key'
                                        ]

                                        if pname in private_key_search_lst:
                                            res = extract_private_keys(f"{so_file}", output_dir=f"{app_name}/extracted_private_keys")

                if has_matches:
                    print(f"{f}:")
                    for m in match_lst:
                        print(m)

                    move_and_rename_if_exists(f, f"{package_name}/")
                else:
                    #remove file
                    fp = Path(f)
                    fp.unlink(missing_ok=True)

        except Exception as e:
            print(f"Error: {e}")

    with open(f"{package_name}/unqiue.secrets.txt", "w", encoding="utf-8") as all_outfile:
         for l in all_match_lst:
             all_outfile.write(f"{l}\n")

    prune_false_positives(f"{package_name}/unqiue.secrets.txt")
    pruned_results = ""
    with open(f"{package_name}/unqiue.secrets.txt", "r", encoding="utf-8") as res_file:
        pruned_results = res_file.readlines()

    #remove the decompiled dir
    shutil.rmtree(f"{package_name}/decompiled")

    # move the completed analysis artifacts to results dir
    print(f"analysis finished. moving package dir to results/")
    shutil.move(f"{package_name}", "results/")
    return pruned_results

class TargetDatabase:
    def __init__(self, db_path="app_targets.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initializes the SQLite database and creates the table if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # We use "APK name" as the PRIMARY KEY since it acts as the unique identifier
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    "APK name" TEXT PRIMARY KEY,
                    "Google Play Store Package URL" TEXT,
                    "Organization Name" TEXT,
                    "Website" TEXT,
                    "Security Program" TEXT,
                    "Security Program Details" TEXT,
                    "Findings" TEXT
                )
            ''')
            conn.commit()

    def get_target(self, apk_name):
        """Retrieves a row by its APK name and converts JSON strings back to lists."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM targets WHERE "APK name" = ?', (apk_name,))
            row = cursor.fetchone()

            if not row:
                return None

            # Convert the sqlite3.Row to a standard dictionary
            result = dict(row)

            # Check if Findings contains data, and convert it back to a list
            if result.get("Findings"):
                try:
                    result["Findings"] = json.loads(result["Findings"])
                except json.JSONDecodeError:
                    # If it wasn't saved as JSON (e.g., old data), leave it as a string
                    pass

            return result

    def set_target(self, apk_name, update_data):
        """Inserts or updates a target, safely converting lists/dicts to JSON strings."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute('INSERT OR IGNORE INTO targets ("APK name") VALUES (?)', (apk_name,))

            if update_data:
                columns = []
                values = []

                for column, value in update_data.items():
                    columns.append(f'"{column}" = ?')

                    # Convert lists (or dicts) to JSON strings before binding
                    if isinstance(value, (list, dict)):
                        values.append(json.dumps(value))
                    else:
                        values.append(value)

                values.append(apk_name)

                query = f'UPDATE targets SET {", ".join(columns)} WHERE "APK name" = ?'
                cursor.execute(query, values)

            conn.commit()

def display_database_records(db_path="app_targets.db", search_findings=None):
    # search database for matches, or return all results
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Retrieve all records from the database
        cursor.execute("SELECT * FROM targets")
        rows = cursor.fetchall()

        match_count = 0

        for row in rows:
            data = dict(row)

            # Parse the findings JSON string back into a Python list
            raw_findings = data.get("Findings")
            if raw_findings:
                try:
                    findings_list = json.loads(raw_findings)
                except json.JSONDecodeError:
                    # Fallback if old data was saved as a raw string instead of JSON
                    findings_list = [raw_findings]
            else:
                findings_list = []

            # If a search term is provided, filter the results
            if search_findings and search_findings.strip():
                # Check if the search term exists in any of the findings (case-insensitive)
                has_match = any(search_findings.lower() in f.lower() for f in findings_list)
                if not has_match:
                    continue  # Skip this database row entirely if there's no match

            match_count += 1

            # Extract fields, defaulting to "N/A" if they are empty/None
            org_name = data.get("Organization Name") or "N/A"
            org_website = data.get("Website") or "N/A"
            appstore_url = data.get("Google Play Store Package URL") or "N/A"
            security_program = data.get("Security Program") or "N/A"

            # Clean up the details string so it doesn't break the single-line tabbed output
            security_program_details = data.get("Security Program Details") or "N/A"
            if security_program_details != "N/A":
                security_program_details = security_program_details.replace("\n", " | ")

            # Print the formatted output
            print(f"org_name: {org_name}\torg_website: https://{org_website}")
            print(f"appstore_url: {appstore_url}\tsecurity_program: {security_program}\tsecurity_program_details: {security_program_details}")
            print("Findings: ")

            if findings_list:
                for f in findings_list:
                    print(f"\t{f}", end="")

                # Ensure the block ends cleanly even if the last finding lacked a \n
                if not findings_list[-1].endswith("\n"):
                    print()
            else:
                print("\tNone")

            print("-" * 80) # Visual separator between apps

        print(f"Total records displayed: {match_count}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start-date", help="The beginning install date of the APKs you want to process")
    parser.add_argument("--end-date", help="The end install date of the APKs you want to process")
    parser.add_argument("-f", "--find-apks", action="store_true", help="Find APKs")
    parser.add_argument("-d", "--download-apks", action="store_true", help="Download APKs")
    parser.add_argument("-a", "--analyze-apks", action="store_true", help="Analyze APKs")
    parser.add_argument("-g", "--get-apk-info", action="store_true", help="Retrieve app developer info from Play Store")
    parser.add_argument("-s", "--search-findings", type=str, nargs='?', const="", default=None, help="Filter the output to only show records where this text exists in the findings.")

    db = TargetDatabase("target_apps.db")

    processed_pkgs = 0
    matching_packages = []

    args = parser.parse_args()

    if args.search_findings is not None:
        display_database_records("target_apps.db", search_findings=args.search_findings)
        return

    if args.start_date:
        dt_date = datetime.strptime(args.start_date, "%Y-%m-%d").date()
    else:
        dt_date = date.today()
    START_DATE = datetime.combine(dt_date, time(0,0,0))
    #print(f"start date: {str(START_DATE)}")

    if args.end_date:
        dt_date = datetime.strptime(args.end_date, "%Y-%m-%d").date()
    else:
        dt_date = date.today()
    END_DATE = datetime.combine(dt_date, time(23, 23, 59))
    #print(f"end date: {str(END_DATE)}")

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler = logging.FileHandler('batch_apk_static_analysis.log', mode='a')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(log_format)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(log_format)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    if args.find_apks:
        # find APKs within specified date range
        matching_packages = get_installed_packages_in_range(START_DATE, END_DATE)
        total_pkgs = len(matching_packages)

        logger.info(f"Found {total_pkgs} packages in given install date range.")

        if not matching_packages:
            logger.info(f"No packages found installed between {START_DATE} and {END_DATE}.")
            return

        for pkg, install_time in matching_packages:
            logger.info(f" - {pkg} (Installed: {install_time})")

        logger.info(f"\nFound {total_pkgs} package(s) in timeframe:")

    if args.download_apks:
        # download APKs within specified date range
        logger.info("\n--- Starting Downloads ---")
        for pkg, _ in matching_packages:
            processed_pkgs += 1
            logger.info(f"\n{processed_pkgs} of {total_pkgs}: Processing {pkg}...")

            dl_result = download_apks_for_package(pkg)

            if dl_result:
                logger.info("downloaded package!")

    if args.analyze_apks:
        # Analyze all APKs within matching_packages (date) range
        logger.info("\n--- Starting Analysis ---")

        if not args.find_apks:
            #default to any APK that hasn't been analyzed yet.
            directory_path = Path('.')
            subdirs = [x for x in directory_path.iterdir() if x.is_dir()]
            for d in subdirs:
                if d != Path('results') and d != Path('__pycache__') and d != Path('venv'):
                    matching_packages.append([d, str(START_DATE)])

        for pkg, _ in matching_packages:
            logger.info("-" * 80)
            logger.info(f"analyzing: {pkg}")
            findings = static_analysis(pkg)
            logger.info("-" * 80)

            delay = random.uniform(4.0, 6.0)
            org_name, org_website, appstore_url = get_apk_info(pkg)
            delay = random.uniform(1.0, 3.0)
            security_program, security_program_details = check_security_txt(org_website)

            logger.info(f"org_name: {org_name}\torg_website: {org_website}\tappstore_url: {appstore_url}\tsecurity_program: {security_program}\tsecurity_program_details: {security_program_details}")
            logger.info(f"Findings: ")
            for f in findings:
                logger.info(f"\t{f}", end="")

            db.set_target(str(pkg), {
                "Google Play Store Package URL": appstore_url,
                "Organization Name": org_name,
                "Website": org_website,
                "Security Program": security_program,
                "Security Program Details": security_program_details,
                "Findings": findings
            })

    logger.info("done!")
    logger.removeHandler(file_handler)
    file_handler.close()
    prune_false_positives("batch_apk_static_analysis.log")


if __name__ == "__main__":
    main()
