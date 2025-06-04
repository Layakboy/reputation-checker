import pandas as pd
import requests
import time
from tkinter import Tk, filedialog
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from tqdm import tqdm
import re
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import WebDriverException, TimeoutException
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# List of common VirusTotal vendors (can be expanded)
COMMON_VT_VENDORS = sorted([
    "Microsoft", "Google", "Kaspersky", "McAfee", "Symantec", "CrowdStrike",
    "Palo Alto Networks", "ESET", "TrendMicro", "BitDefender", "Sophos",
    "Avast", "AVG", "Malwarebytes", "F-Secure", "Fortinet", "Check Point",
    "Cisco", "SentinelOne", "Cybereason", "GData", "Comodo", "VIPRE",
    "Emsisoft", "ZoneAlarm", "DrWeb", "Ikarus", "ClamAV", "Bkav", "TotalDefense",
    "McAfee", "McAfee-GW-Edition"
])

# List of API keys
api_keys = [
    'd70a0b180f31c230fbc27e0704a3d58ebae6eb3a504de183e8d522cf59b4ec3b',
    '0139d5f98e260b56d7ff3c96e276406de36a2e2430da683d6e92865531223d66',
    '08e131fb5f477e6c4333476e2b99f9a7ba7c586a3bad4c39a43a1756fd7c27ac',
    '78cb6e7581f918142e4ac3080d6112b1833c3736392e5f4d63792f78888edfca',
    'c44515ee67dcb60a84d1930905a8e55dc4eb70c1e49bb165cdf938d1f3f930f7',
    'cf651d39e830f9eb24817e9b4fda19c267dfa69106b847411602fbafc40d7d5d',
    '352bcd0eefc96877c5dc26b13a7449b1b85168fa307fe4c39dd394ac75450ab4',
]

# Path to ChromeDriver executable for Selenium Talos lookups
# Default to the chromedriver included with this project. Adjust the path if
# running on another system.
import os
CHROMEDRIVER_PATH = os.path.join(os.path.dirname(__file__), "chromedriver.exe")


class APIKeyManager:
    """Manage API keys safely across threads."""

    def __init__(self, api_keys):
        self.api_keys = api_keys.copy()
        self.lock = threading.Lock()
        self.index = 0

    def get_api_key(self):
        with self.lock:
            if not self.api_keys:
                return None
            api_key = self.api_keys[self.index % len(self.api_keys)]
            self.index += 1
            return api_key

    def remove_api_key(self, api_key):
        with self.lock:
            if api_key in self.api_keys:
                self.api_keys.remove(api_key)
                if self.index >= len(self.api_keys):
                    self.index = 0


def normalize_ioc(ioc: str) -> str:
    """Normalize IOC notation."""
    ioc = ioc.replace('[.]', '.').replace('(.)', '.')
    ioc = ioc.replace('[://]', '://').replace('[:]', ':').replace('[', '').replace(']', '')
    ioc = ioc.replace('hxxp://', 'http://').replace('hxxps://', 'https://')
    return ioc.strip()


def extract_iocs_from_excel(excel_file):
    """Extract and categorize IOCs from an Excel file."""
    try:
        df = pd.read_excel(excel_file)
    except Exception as e:
        print(f"Error reading Excel file: {e}")
        return {}, 0, 0

    iocs = {
        'URL': [],
        'FileHash-MD5': [],
        'FileHash-SHA1': [],
        'FileHash-SHA256': [],
        'domain': [],
        'hostname': [],
        'ip': []
    }
    seen_iocs = set()
    total_read = 0
    duplicates_skipped = 0

    if len(df.columns) < 2:
        print("Error: Excel file must have at least two columns (Type and IOC).")
        return {}, 0, 0

    type_col_index = 0
    ioc_col_index = 1

    for _, row in df.iterrows():
        if pd.isna(row.iloc[type_col_index]) or pd.isna(row.iloc[ioc_col_index]):
            continue

        total_read += 1
        ioc_type_raw = str(row.iloc[type_col_index]).lower().strip()
        ioc_value = normalize_ioc(str(row.iloc[ioc_col_index]))

        if not ioc_value:
            continue

        if ioc_value in seen_iocs:
            duplicates_skipped += 1
            continue
        seen_iocs.add(ioc_value)

        if 'url' in ioc_type_raw:
            iocs['URL'].append(ioc_value)
        elif 'domain' in ioc_type_raw:
            iocs['domain'].append(ioc_value)
        elif 'hostname' in ioc_type_raw:
            iocs['hostname'].append(ioc_value)
        elif 'ip' in ioc_type_raw:
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc_value):
                iocs['ip'].append(ioc_value)
            elif '.' in ioc_value:
                iocs['hostname'].append(ioc_value)
        elif 'md5' in ioc_type_raw:
            if len(ioc_value) == 32:
                iocs['FileHash-MD5'].append(ioc_value)
        elif 'sha1' in ioc_type_raw:
            if len(ioc_value) == 40:
                iocs['FileHash-SHA1'].append(ioc_value)
        elif 'sha256' in ioc_type_raw:
            if len(ioc_value) == 64:
                iocs['FileHash-SHA256'].append(ioc_value)

    return iocs, total_read, duplicates_skipped


def standardize_software_name(names, file_hash, vendors_results):
    """Return standardized software info from VT names."""
    if not names:
        return {"standard_name": "Unknown", "confidence": "Low", "classification": "Unknown"}

    names = [name.lower() for name in names]

    legitimate_patterns = {
        r'microsoft|msft': 'Microsoft',
        r'chrome|google': 'Google',
        r'firefox|mozilla': 'Mozilla',
        r'adobe': 'Adobe',
        r'oracle|java': 'Oracle',
        r'vmware': 'VMware',
        r'python': 'Python',
        r'node\.?js': 'Node.js',
        r'winzip|7zip|7-zip': 'Compression Tool',
        r'notepad\+\+': 'Notepad++',
        r'visual studio|vscode': 'Visual Studio'
    }

    for pattern, vendor in legitimate_patterns.items():
        if any(re.search(pattern, name) for name in names):
            malicious_count = sum(
                1 for result in vendors_results.values() if result.get('category') == 'malicious'
            )
            if malicious_count == 0:
                classification = "Legitimate"
                confidence = "High"
            elif malicious_count < 3:
                classification = "Suspicious (Low Risk)"
                confidence = "Medium"
            else:
                classification = "Suspicious (High Risk)"
                confidence = "Medium"
            return {
                "standard_name": f"{vendor} Software",
                "confidence": confidence,
                "classification": classification,
            }

    if names:
        most_common = max(set(names), key=names.count)
        cleaned_name = re.sub(r'[^\w\s\-\.]', '', most_common).strip()
        cleaned_name = re.sub(r'\s+', ' ', cleaned_name)
        malicious_count = sum(
            1 for result in vendors_results.values() if result.get('category') == 'malicious'
        )
        if malicious_count > 5:
            classification = "Malicious"
            confidence = "High"
        elif malicious_count > 0:
            classification = "Suspicious"
            confidence = "Medium"
        else:
            classification = "Unknown"
            confidence = "Low"
        return {
            "standard_name": cleaned_name.title(),
            "confidence": confidence,
            "classification": classification,
        }

    return {"standard_name": "Unknown", "confidence": "Low", "classification": "Unknown"}


def check_ioc_talos(ioc, ioc_type, delay=3):
    """Check IOC against Talos Intelligence."""
    base_url = "https://talosintelligence.com/"
    if ioc_type in ['domain', 'hostname']:
        url = f"{base_url}reputation_center/lookup?search={ioc}"
    elif ioc_type == 'ip':
        url = f"{base_url}reputation_center/lookup?search={ioc}"
    elif ioc_type in ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']:
        url = f"{base_url}reputation_center/lookup?search={ioc}"
    elif ioc_type == 'URL':
        try:
            from urllib.parse import urlparse

            parsed = urlparse(ioc)
            domain = parsed.netloc
            url = f"{base_url}reputation_center/lookup?search={domain}"
        except Exception:
            url = f"{base_url}reputation_center/lookup?search={ioc}"
    else:
        return {
            "ioc": ioc,
            "talos_verdict": "Unsupported Type",
            "talos_category": "Unknown",
            "talos_confidence": "N/A",
        }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        time.sleep(delay)
        tqdm.write(f"Checking Talos for {ioc_type}: {ioc}")
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            return {
                "ioc": ioc,
                "talos_verdict": f"HTTP Error {response.status_code}",
                "talos_category": "Error",
                "talos_confidence": "N/A",
            }

        soup = BeautifulSoup(response.text, "html.parser")
        verdict = "Unknown"
        category = "Unknown"
        confidence = "Low"

        reputation_elements = soup.find_all(
            text=re.compile(r"(Good|Neutral|Poor|Malicious|Clean|Suspicious)", re.IGNORECASE)
        )
        if reputation_elements:
            verdict = reputation_elements[0].strip()
            confidence = "Medium"

        rep_indicators = soup.find_all('div', class_=re.compile(r'reputation|status|verdict', re.IGNORECASE))
        for indicator in rep_indicators:
            text = indicator.get_text().strip().lower()
            if any(term in text for term in ['good', 'clean', 'benign']):
                verdict = "Good"
                category = "Benign"
                confidence = "High"
                break
            elif any(term in text for term in ['poor', 'malicious', 'bad']):
                verdict = "Poor"
                category = "Malicious"
                confidence = "High"
                break
            elif any(term in text for term in ['neutral', 'unknown']):
                verdict = "Neutral"
                category = "Unknown"
                confidence = "Medium"

        return {
            "ioc": ioc,
            "talos_verdict": verdict,
            "talos_category": category,
            "talos_confidence": confidence,
        }

    except requests.exceptions.RequestException as e:
        tqdm.write(f"Network error checking Talos for {ioc}: {e}")
        return {
            "ioc": ioc,
            "talos_verdict": f"Network Error: {str(e)}",
            "talos_category": "Error",
            "talos_confidence": "N/A",
        }
    except Exception as e:
        tqdm.write(f"Error parsing Talos response for {ioc}: {e}")
        return {
            "ioc": ioc,
            "talos_verdict": f"Parse Error: {str(e)}",
            "talos_category": "Error",
            "talos_confidence": "N/A",
        }


def check_ioc_talos_selenium(ioc, ioc_type, service, chrome_options, timeout=10):
    """Check IOC against Talos using Selenium."""
    base_url = "https://talosintelligence.com/"
    if ioc_type in ["domain", "hostname", "ip"]:
        lookup = ioc
    elif ioc_type in ["FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"]:
        lookup = ioc
    elif ioc_type == "URL":
        try:
            from urllib.parse import urlparse
            lookup = urlparse(ioc).netloc
        except Exception:
            lookup = ioc
    else:
        return {
            "ioc": ioc,
            "talos_verdict": "Unsupported Type",
            "talos_category": "Unknown",
            "talos_confidence": "N/A",
        }

    url = f"{base_url}reputation_center/lookup?search={lookup}"

    driver = None
    try:
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(timeout)
        tqdm.write(f"Checking Talos (Selenium) for {ioc_type}: {ioc}")
        driver.get(url)
        WebDriverWait(driver, timeout).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".reputation-score"))
        )
        time.sleep(1)
        page_source = driver.page_source
    except (WebDriverException, TimeoutException) as e:
        return {
            "ioc": ioc,
            "talos_verdict": f"Error: {str(e)}",
            "talos_category": "Error",
            "talos_confidence": "N/A",
        }
    finally:
        if driver:
            driver.quit()

    soup = BeautifulSoup(page_source, "html.parser")
    verdict = "Unknown"
    category = "Unknown"
    confidence = "Low"

    verdict_elem = soup.find("div", class_="well-reputation") or soup.find(
        "div", class_="reputation-score"
    )
    if verdict_elem:
        verdict = verdict_elem.get_text(strip=True)

    text_content = soup.get_text()
    cat_match = re.search(r"Category\s*:\s*(Benign|Suspicious|Malicious)", text_content, re.I)
    if cat_match:
        category = cat_match.group(1).title()

    conf_match = re.search(r"Confidence\s*:\s*(High|Medium|Low)", text_content, re.I)
    if conf_match:
        confidence = conf_match.group(1).title()

    return {
        "ioc": ioc,
        "talos_verdict": verdict,
        "talos_category": category,
        "talos_confidence": confidence,
    }


def check_ioc_comprehensive(
    ioc,
    ioc_type,
    api_key_manager,
    selected_vendors=None,
    include_talos=True,
    driver_path=None,
    chrome_options=None,
    timeout=10,
    delay=2,
):
    """Check IOC against both VirusTotal and Talos."""
    vt_result = check_ioc_virustotal(
        ioc, ioc_type, api_key_manager, selected_vendors, delay
    )
    talos_result = {}
    if include_talos and chrome_options:
        try:
            if driver_path:
                service = Service(driver_path)
            else:
                service = Service(ChromeDriverManager().install())
            talos_result = check_ioc_talos_selenium(
                ioc, ioc_type, service, chrome_options, timeout
            )
        except Exception as e:
            print(f"Talos check failed: {str(e)}")
            talos_result = {
                "talos_verdict": "Check Failed",
                "talos_category": "Error",
                "talos_confidence": "N/A",
            }

    combined = vt_result.copy()
    if include_talos and talos_result:
        combined.update({
            "talos_verdict": talos_result.get("talos_verdict", "N/A"),
            "talos_category": talos_result.get("talos_category", "N/A"),
            "talos_confidence": talos_result.get("talos_confidence", "N/A"),
        })
    else:
        combined.update({
            "talos_verdict": "Not Checked",
            "talos_category": "N/A",
            "talos_confidence": "N/A",
        })
    return combined


def check_ioc_virustotal(ioc, ioc_type, api_key_manager, selected_vendors=None, delay=2):
    """Query the VirusTotal API for an IOC."""
    while True:
        api_key = api_key_manager.get_api_key()
        if api_key is None:
            return {
                "ioc": ioc,
                "ioc_type_input": ioc_type,
                "result": "Error: All API keys exhausted",
                "malicious_count": 0,
                "app_names": ["N/A"],
                "hashes": {},
                "detected_by_vendors": [],
                "software_info": {
                    "standard_name": "Unknown",
                    "confidence": "Low",
                    "classification": "Error",
                },
            }

        headers = {"x-apikey": api_key}
        is_file_hash = ioc_type in ["FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"]

        if ioc_type == "URL":
            ioc_clean = normalize_ioc(ioc)
            ioc_encoded = base64.urlsafe_b64encode(ioc_clean.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{ioc_encoded}"
        elif ioc_type == "ip":
            ioc_clean = normalize_ioc(ioc)
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_clean}"
        elif is_file_hash:
            ioc_clean = normalize_ioc(ioc)
            url = f"https://www.virustotal.com/api/v3/files/{ioc_clean}"
        elif ioc_type in ["domain", "hostname"]:
            ioc_clean = normalize_ioc(ioc)
            url = f"https://www.virustotal.com/api/v3/domains/{ioc_clean}"
        else:
            return {
                "ioc": ioc,
                "ioc_type_input": ioc_type,
                "result": f"Unknown IOC type: {ioc_type}",
                "malicious_count": 0,
                "app_names": ["N/A"],
                "hashes": {},
                "detected_by_vendors": [],
                "software_info": {
                    "standard_name": "Unknown",
                    "confidence": "Low",
                    "classification": "Error",
                },
            }

        try:
            time.sleep(delay)
            tqdm.write(
                f"Checking VirusTotal {ioc_type}: {ioc_clean} (Using key {api_key[:8]}...)"
            )
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                if "data" in data and "attributes" in data["data"]:
                    attributes = data["data"]["attributes"]
                    all_vendors_results = attributes.get("last_analysis_results", {})

                    if selected_vendors is None or selected_vendors == "All":
                        vendors_to_consider = all_vendors_results
                    else:
                        selected_vendors_lower = {v.lower() for v in selected_vendors}
                        vendors_to_consider = {
                            vendor_name: result
                            for vendor_name, result in all_vendors_results.items()
                            if vendor_name.lower() in selected_vendors_lower
                        }

                    malicious_count = 0
                    detecting_vendors_list = []
                    for vendor_name, result in vendors_to_consider.items():
                        if result.get("category") == "malicious":
                            malicious_count += 1
                            detecting_vendors_list.append(vendor_name)

                    names = attributes.get("names", []) if is_file_hash else []
                    app_names = names if names else ["N/A"]
                    software_info = standardize_software_name(
                        names, ioc_clean, all_vendors_results
                    )

                    file_hashes = {}
                    if is_file_hash:
                        file_hashes['sha256'] = attributes.get('sha256')
                        file_hashes['sha1'] = attributes.get('sha1')
                        file_hashes['md5'] = attributes.get('md5')
                        file_hashes = {k: v for k, v in file_hashes.items() if v}

                    if malicious_count > 0:
                        result_text = (
                            f"Malicious (detected by {malicious_count} selected vendors)"
                        )
                    else:
                        result_text = "Not malicious or undetected by selected vendors"

                    return {
                        "ioc": ioc,
                        "ioc_type_input": ioc_type,
                        "result": result_text,
                        "malicious_count": malicious_count,
                        "app_names": app_names,
                        "hashes": file_hashes,
                        "detected_by_vendors": detecting_vendors_list,
                        "software_info": software_info,
                    }
                else:
                    return {
                        "ioc": ioc,
                        "ioc_type_input": ioc_type,
                        "result": "No analysis data available in VirusTotal",
                        "malicious_count": 0,
                        "app_names": ["N/A"],
                        "hashes": {},
                        "detected_by_vendors": [],
                        "software_info": {
                            "standard_name": "Unknown",
                            "confidence": "Low",
                            "classification": "Unknown",
                        },
                    }

            elif response.status_code == 401:
                tqdm.write(
                    f"Unauthorized: Invalid API key {api_key[:8]}. Removing key."
                )
                api_key_manager.remove_api_key(api_key)
                continue
            elif response.status_code in (403, 429):
                tqdm.write(
                    f"API key quota exhausted for key {api_key[:8]}. Removing key."
                )
                api_key_manager.remove_api_key(api_key)
                continue
            elif response.status_code == 404:
                return {
                    "ioc": ioc,
                    "ioc_type_input": ioc_type,
                    "result": "Not found in VirusTotal",
                    "malicious_count": 0,
                    "app_names": ["N/A"],
                    "hashes": {},
                    "detected_by_vendors": [],
                    "software_info": {
                        "standard_name": "Unknown",
                        "confidence": "Low",
                        "classification": "Not Found",
                    },
                }
            else:
                tqdm.write(
                    f"HTTP Error {response.status_code} for IOC {ioc_clean} with key {api_key[:8]}."
                )
                return {
                    "ioc": ioc,
                    "ioc_type_input": ioc_type,
                    "result": f"HTTP Error {response.status_code}",
                    "malicious_count": 0,
                    "app_names": ["N/A"],
                    "hashes": {},
                    "detected_by_vendors": [],
                    "software_info": {
                        "standard_name": "Unknown",
                        "confidence": "Low",
                        "classification": "Error",
                    },
                }

        except requests.exceptions.RequestException as e:
            tqdm.write(
                f"Network Error processing IOC {ioc_clean} with API key {api_key[:8]}: {e}. Removing key and retrying."
            )
            api_key_manager.remove_api_key(api_key)
            continue
        except Exception as e:
            tqdm.write(
                f"Unexpected Error processing IOC {ioc_clean} with API key {api_key[:8]}: {e}. Removing key."
            )
            api_key_manager.remove_api_key(api_key)
            return {
                "ioc": ioc,
                "ioc_type_input": ioc_type,
                "result": f"Unexpected Processing Error: {e}",
                "malicious_count": 0,
                "app_names": ["N/A"],
                "hashes": {},
                "detected_by_vendors": [],
                "software_info": {
                    "standard_name": "Unknown",
                    "confidence": "Low",
                    "classification": "Error",
                },
            }


def assign_severity(result_dict):
    """Assign severity based on VT and Talos results."""
    classification = result_dict["software_info"]["classification"]
    malicious_count = result_dict["malicious_count"]
    talos_verdict = result_dict.get("talos_verdict", "N/A")
    talos_category = result_dict.get("talos_category", "N/A")

    if (
        classification == "Malicious"
        or "Malicious" in classification
        or malicious_count >= 5
        or talos_category == "Malicious"
        or talos_verdict in ["Poor", "Malicious"]
    ):
        return "High"

    if (malicious_count > 0 and malicious_count < 5) or talos_verdict == "Suspicious":
        return "Medium"

    if (
        classification == "Unknown"
        or "Not Found" in classification
        or "Error" in classification
        or talos_verdict in ["Unknown", "Error"]
    ):
        return "Low"

    if (
        classification == "Legitimate"
        or malicious_count == 0
        or talos_verdict in ["Good", "Clean"]
        or talos_category == "Benign"
    ):
        return "Very Low"

    return "Low"


def get_filename(app_names_list):
    """Return the first filename from VT names list."""
    if app_names_list and app_names_list != ["N/A"]:
        valid_names = [name for name in app_names_list if name and isinstance(name, str)]
        if valid_names:
            first_name = valid_names[0]
            if isinstance(first_name, list) and first_name:
                first_name = first_name[0]
            if isinstance(first_name, str):
                return first_name
    return "Unknown"


def process_iocs_concurrently(
    iocs,
    api_keys,
    selected_vendors=None,
    include_talos=True,
    driver_path=None,
    timeout=10,
):
    """Process IOCs concurrently using VirusTotal and Talos."""
    results = []
    unique_iocs_count = sum(len(ioc_list) for ioc_list in iocs.values())
    api_key_manager = APIKeyManager(api_keys)

    # Updated Chrome options with additional flags for stability and to suppress warnings
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--dns-prefetch-disable")
    chrome_options.add_argument("--disable-infobars")
    chrome_options.add_argument("--enable-unsafe-swiftshader")  # Added to handle WebGL warning
    chrome_options.add_argument("--disable-software-rasterizer")  # Disable software rasterization
    chrome_options.add_argument("--disable-logging")  # Disable logging
    chrome_options.add_argument("--log-level=3")  # Set log level to ERROR only
    chrome_options.add_argument("--silent")  # Minimize console output
    chrome_options.add_argument("--disable-in-process-stack-traces")  # Disable stack traces
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])  # Disable DevTools logging
    chrome_options.page_load_strategy = 'eager'

    with ThreadPoolExecutor(max_workers=2) as executor:  # Reduced workers for stability
        future_to_ioc = {}
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list:
                future = executor.submit(
                    check_ioc_comprehensive,
                    ioc,
                    ioc_type,
                    api_key_manager,
                    selected_vendors,
                    include_talos,
                    driver_path,
                    chrome_options,
                    timeout,
                )
                future_to_ioc[future] = (ioc, ioc_type)

        with tqdm(total=unique_iocs_count, desc="Processing IOCs") as pbar:
            for future in as_completed(future_to_ioc):
                ioc_input, ioc_type_input = future_to_ioc[future]
                try:
                    result_dict = future.result()
                    final_ioc = result_dict["ioc"]
                    final_type = result_dict["ioc_type_input"]
                    is_file_hash = final_type in [
                        "FileHash-MD5",
                        "FileHash-SHA1",
                        "FileHash-SHA256",
                    ]
                    hashes = result_dict.get("hashes", {})

                    if is_file_hash and hashes:
                        if hashes.get("sha256"):
                            final_ioc = hashes["sha256"]
                            final_type = "FileHash-SHA256"
                        elif hashes.get("md5"):
                            final_ioc = hashes["md5"]
                            final_type = "FileHash-MD5"
                        elif hashes.get("sha1"):
                            final_ioc = hashes["sha1"]
                            final_type = "FileHash-SHA1"

                    severity = assign_severity(result_dict)
                    filename = get_filename(result_dict.get("app_names", []))
                    detecting_vendors_list = result_dict.get("detected_by_vendors", [])
                    detected_by_str = (
                        ", ".join(detecting_vendors_list)
                        if detecting_vendors_list
                        else "Not Detected"
                    )

                    result_entry = {
                        "Type": final_type,
                        "IOC": final_ioc,
                        "VT_Result": result_dict["result"],
                        "Talos_Verdict": result_dict.get("talos_verdict", "N/A"),
                        "Severity": severity,
                        "Filename": filename,
                        "VT_Detected_By": detected_by_str,
                        "VT_Malicious_Count": result_dict["malicious_count"],
                        "Talos_Category": result_dict.get("talos_category", "N/A"),
                        "Talos_Confidence": result_dict.get("talos_confidence", "N/A"),
                    }
                    results.append(result_entry)
                except Exception as exc:
                    tqdm.write(
                        f"IOC {ioc_input} (Type: {ioc_type_input}) generated an exception: {exc}"
                    )
                    results.append(
                        {
                            "Type": ioc_type_input,
                            "IOC": ioc_input,
                            "VT_Result": f"Processing Error: {exc}",
                            "Talos_Verdict": "Error",
                            "Severity": "Low",
                            "Filename": "Unknown",
                            "VT_Detected_By": "Error",
                            "VT_Malicious_Count": 0,
                            "Talos_Category": "Error",
                            "Talos_Confidence": "N/A",
                        }
                    )
                finally:
                    pbar.update(1)

    return results


def output_to_excel(results, output_base, total_read, duplicates_skipped):
    """Write results and severity breakdown to an Excel file."""
    if not output_base.endswith('.xlsx'):
        output_file = f"{output_base}.xlsx"
    else:
        output_file = output_base

    df_results = pd.DataFrame(results)
    if not df_results.empty:
        df_results.drop_duplicates(subset=['IOC'], keep='first', inplace=True)

    severity_columns = [
        "Type",
        "IOC",
        "Filename",
        "VT_Detected_By",
        "Talos_Verdict",
        "Severity",
    ]

    high_severity_df = df_results[df_results["Severity"] == "High"][severity_columns].copy()
    medium_severity_df = df_results[df_results["Severity"] == "Medium"][severity_columns].copy()
    low_severity_df = df_results[df_results["Severity"] == "Low"][severity_columns].copy()
    very_low_severity_df = df_results[df_results["Severity"] == "Very Low"][severity_columns].copy()

    with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
        df_results.to_excel(writer, index=False, sheet_name="All_Results")
        high_severity_df.to_excel(writer, index=False, sheet_name="High_Severity")
        medium_severity_df.to_excel(writer, index=False, sheet_name="Medium_Severity")
        low_severity_df.to_excel(writer, index=False, sheet_name="Low_Severity")
        very_low_severity_df.to_excel(writer, index=False, sheet_name="Very_Low_Severity")

        summary_df = pd.DataFrame(
            {
                "Metric": [
                    "Total IOCs Read",
                    "Duplicates Skipped",
                    "Unique IOCs Processed",
                    "High Severity",
                    "Medium Severity",
                    "Low Severity",
                    "Very Low Severity",
                ],
                "Value": [
                    total_read,
                    duplicates_skipped,
                    len(df_results),
                    len(high_severity_df),
                    len(medium_severity_df),
                    len(low_severity_df),
                    len(very_low_severity_df),
                ],
            }
        )
        summary_df.to_excel(writer, index=False, sheet_name="Summary")

    return output_file


def main():
    """Basic CLI for processing an Excel file of IOCs."""
    try:
        root = Tk()
        root.withdraw()
        input_file = filedialog.askopenfilename(
            title="Select IOC Excel File", filetypes=[("Excel files", "*.xlsx *.xls")]
        )
        if not input_file:
            print("No input file selected.")
            return

        output_file = filedialog.asksaveasfilename(
            title="Save Output Excel", defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")]
        )
        if not output_file:
            print("No output file selected.")
            return

        iocs, total_read, duplicates_skipped = extract_iocs_from_excel(input_file)
        if not iocs:
            print("No IOCs extracted.")
            return

        results = process_iocs_concurrently(
            iocs,
            api_keys,
            selected_vendors=COMMON_VT_VENDORS,
            include_talos=True,
            driver_path=CHROMEDRIVER_PATH,
            timeout=10,
        )
        saved_file = output_to_excel(results, output_file, total_read, duplicates_skipped)
        print(f"Results saved to {saved_file}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        raise

if __name__ == "__main__":
    main()
