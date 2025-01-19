import streamlit as st
import requests
import json
import pandas as pd
import re
import urllib.parse

st.markdown(
    """
    <style>
    .css-1jc7ptx, .e1ewe7hr3, .viewerBadge_container__1QSob,
    .styles_viewerBadge__1yB5_, .viewerBadge_link__1S137,
    .viewerBadge_text__1JaDK {
        display: none;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# VirusTotal API Key
VT_API_KEY = "b208107450f8af1b55f735fe4377820a4b6baef21d5734c383a099e3271796ee"

# AbuseIPDB API Key
ABUSEIPDB_API_KEY = "a81598f36599471d707ce45964fa0eaddd91127e934f7dbb52b33d829adc0e9982b3ce83334d3546"

# Hybrid-Analysis API Key
HYBRID_API_KEY = "353qykml83fafbd44gyra3nlc99268b99euha3880b9f6801e41fgho52db60e64"


# Function to get VirusTotal report
def get_vt_report(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching VT report: {e}")
        return None

# Function to get AbuseIPDB report
def get_abuseipdb_report(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip_address}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Raise an exception for bad status codes
        # with open('abuse_report.txt', 'w') as f:
        #     json.dump(response.json(), f, indent=4)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching AbuseIPDB report: {e}")
        return None

# Function to get Who.is report
def get_whois_report(ip_address):
    url = "https://who.is/whois-ip/ip-address/" + ip_address
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching Who.is report: {e}")
        return None


# Function to get Hybrid-Analysis report
def get_hybrid_report(hash_value):
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {
        "api-key": HYBRID_API_KEY,
        "User  -Agent": "Falcon Sandbox",
        "Content-Type": "application/x-www-form-urlencoded",
        "accept": "application/json"
    }
    data = {"hash": hash_value}
    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()  # Raise an exception for bad status codes
        # with open('hybrid_analysis_report.txt', 'w') as f:
        #     json.dump(response.json(), f, indent=4)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching Hybrid-Analysis report: {e}")
        return None
    
# Function to get VirusTotal report for hash
def get_vt_report_hash(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  
        # with open('vt_report.txt', 'w') as f:
        #     json.dump(response.json(), f, indent=4)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching VirusTotal report for hash: {e}")
        return None
    
# Function to get VirusTotal report for domain
def get_vt_report_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        # with open('vt_domainreport.txt', 'w') as f:
        #     json.dump(response.json(), f, indent=4)
        return response.json()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching VirusTotal report for domain: {e}")
        return None


# Streamlit interface
st.title("Bulk IP Address and Hash Checker")

tab_ip, tab_hash, tab_domain, tab_about = st.tabs(["IP Address", "Hash", "Domain", "About"])

with tab_ip:
    upload_file = st.file_uploader("Upload a txt file with IPs separated by newlines", type=["txt"])
    if upload_file:
        ip_addresses = upload_file.read().decode("utf-8").splitlines()
    else:
        ip_addresses = st.text_input("Enter IP addresses separated by commas:")

    reports = st.multiselect("Select Reports", ["VirusTotal", "AbuseIPDB", "Who.is"], default=["VirusTotal", "AbuseIPDB", "Who.is"])
    st.write("Please refrain from using VirusTotal if more than 4 IPs involved!")

    st.markdown("""
<a href="#" data-toggle="tooltip" title="API Limitations: 
VirusTotal: 4 requests per minute
AbuseIPDB: 100 requests per day
Who.is: No API limitations specified">API limitations</a>
""", unsafe_allow_html=True)

    if st.button("Check IP", key="check_ip"):
        if upload_file:
            ip_addresses_list = ip_addresses
        else:
            ip_addresses_list = [ip.strip() for ip in ip_addresses.split(",")]
        data = []
        for ip_address in ip_addresses_list:
            vt_report = None
            abuseipdb_report = None
            whois_report = None
            if "VirusTotal" in reports:
                vt_report = get_vt_report(ip_address)
            if "AbuseIPDB" in reports:
                abuseipdb_report = get_abuseipdb_report(ip_address)
            if "Who.is" in reports:
                whois_report = get_whois_report(ip_address)
            row = {
                "IP Address": ip_address,
                "VirusTotal": {
                    "Malicious": vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) if vt_report else "",
                    "Suspicious": vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", 0) if vt_report else "",
                    "Undetected": vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("undetected", 0) if vt_report else "",
                    "Harmless": vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("harmless", 0) if vt_report else "",
                    "Detected URLs": len(vt_report.get("data", {}).get("attributes", {}).get("last_analysis_results", [])) if vt_report else 0,
                    "Country": vt_report.get("data", {}).get("attributes", {}).get("country", "") if vt_report else "",
                    "ASN": vt_report.get("data", {}).get("attributes", {}).get("asn", "") if vt_report else "",
                    "Tags": vt_report.get("data", {}).get("attributes", {}).get("tags", []) if vt_report else [],
                },
                "AbuseIPDB": {
                    "Country Code": abuseipdb_report.get("data", {}).get("countryCode", "") if abuseipdb_report else "",
                    "ISP": abuseipdb_report.get("data", {}).get("isp", "") if abuseipdb_report else "",
                    "Abuse Confidence Score": abuseipdb_report.get("data", {}).get("abuseConfidenceScore", 0) if abuseipdb_report else 0,
                    "Total Reports": abuseipdb_report.get("data", {}).get("totalReports", 0) if abuseipdb_report else 0,
                    "Last Reported At": abuseipdb_report.get("data", {}).get("lastReportedAt", "") if abuseipdb_report else ""
                },
                "Who.is": {
                    "Organization": "",
                    "CIDR": "",
                    "Range": ""
                }
            }
            if whois_report:
                whois_text = whois_report
                organization = ""
                cidr = ""
                ip_range = ""
                for line in whois_text.splitlines():
                    if "Organization:" in line:
                        organization = re.search(r'Organization:(.*)', line).group(1).strip()
                    elif "CIDR:" in line:
                        cidr = re.search(r'CIDR:(.*)', line).group(1).strip()
                    elif "Range:" in line:
                        ip_range = re.search(r'Range:(.*)', line).group(1).strip()
                row["Who.is"]["Organization"] = organization
                row["Who.is"]["CIDR"] = cidr
                row["Who.is"]["Range"] = ip_range
            data.append(row)
        if "VirusTotal" in reports:
            df_vt = pd.DataFrame([{"IP Address": d["IP Address"], 
                                   "Malicious": f"{d['VirusTotal']['Malicious']}/94",
                                   "Undetected": d["VirusTotal"]["Undetected"], 
                                   "Harmless": d["VirusTotal"]["Harmless"], 
                                   "Suspicious": d["VirusTotal"]["Suspicious"], 
                                   "Country": d["VirusTotal"]["Country"], 
                                   "ASN": d["VirusTotal"]["ASN"], 
                                   "Tags": ', '.join(d["VirusTotal"]["Tags"]),
                                   "Link": f"https://www.virustotal.com/gui/ip-address/{d['IP Address']}"} for d in data if d["IP Address"] is not None and d["IP Address"] != ""])
            st.write("VirusTotal Report:")
            st.write(df_vt)
        if "AbuseIPDB" in reports:
            df_abuseipdb = pd.DataFrame([{"IP Address": d["IP Address"], 
                                          "Country Code": d["AbuseIPDB"]["Country Code"], 
                                          "ISP": d["AbuseIPDB"]["ISP"], 
                                          "Abuse Confidence Score": f"{d['AbuseIPDB']['Abuse Confidence Score']}/100",
                                          "Total Reports": d["AbuseIPDB"]["Total Reports"], 
                                          "Last Reported At": d["AbuseIPDB"]["Last Reported At"],
                                          "Link": f"https://www.abuseipdb.com/check/{d['IP Address']}"} for d in data if d["IP Address"] is not None and d["IP Address"] != ""])
            st.write(df_abuseipdb)
        if "Who.is" in reports:
            df_whois = pd.DataFrame([{"IP Address": d["IP Address"], 
                                      "Organization": d ["Who.is"]["Organization"], 
                                      "CIDR": d["Who.is"]["CIDR"], 
                                      "Range": d["Who.is"]["Range"],
                                      "Link": f"https://who.is/whois-ip/ip-address/{d['IP Address']}"} for d in data if d["IP Address"] is not None and d["IP Address"] != ""])
            st.write("Who.is Report:")
            st.write(df_whois)

with tab_hash:
    upload_file = st.file_uploader("Upload a txt file with hashes separated by newlines", type=["txt"])
    if upload_file:
        hash_values = upload_file.read().decode("utf-8").splitlines()
    else:
        hash_values = st.text_input("Enter hash values separated by commas:")

    reports = st.multiselect("Select Reports", ["VirusTotal", "Hybrid-Analysis"], default=["VirusTotal", "Hybrid-Analysis"])
    st.write("Please refrain from using VirusTotal if more than 4 Hashes involved!")
    st.markdown("""
<a href="#" data-toggle="tooltip" title="API Limitations: 
VirusTotal: 4 requests per minute
Hybrid-Analysis: 100 requests per day">API limitations</a>
""", unsafe_allow_html=True)

    if st.button("Check Hash", key="check_hash"):
        if upload_file:
            hash_values_list = hash_values
        else:
            hash_values_list = [hash_value.strip() for hash_value in hash_values.split(",")]
        
        data = []
        for hash_value in hash_values_list:
            vt_report = None
            hybrid_report = None
            
            if "VirusTotal" in reports:
                vt_report = get_vt_report_hash(hash_value)
            
            if "Hybrid-Analysis" in reports:
                hybrid_report = get_hybrid_report(hash_value)
            row = {
                "Hash Value": hash_value,
                "VirusTotal": {
                    "SHA1": vt_report.get("data", {}).get("attributes", {}).get("sha1", 0) if vt_report else "",
                    "Malicious": vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) if vt_report else "No matches found!",
                    "Suspicious": vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", 0) if vt_report else "",
                    "Undetected": vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("undetected", 0) if vt_report else "",
                    "Harmless": vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("harmless", 0) if vt_report else "",
                    "Tags": vt_report.get("data", {}).get("attributes", {}).get("meaningful_name", 0) if vt_report else "No matches found!",
                    "Popular Threat Classification": vt_report.get("data", {}).get("attributes", {}).get("popular_threat_classification", {}).get("suggested_threat_label", "") if vt_report else "No matches found!"
                },
                "Hybrid-Analysis": {
                    "Threat Score": hybrid_report[0].get("threat_score", 0) if hybrid_report else 0,
                    "Threat Level": hybrid_report[0].get("threat_level", "") if hybrid_report else "",
                    "Verdict": hybrid_report[0].get("verdict", "") if hybrid_report else "",
                    "AV Detect": hybrid_report[0].get("av_detect", 0) if hybrid_report else 0,
                    "VX Family": hybrid_report[0].get("vx_family", "") if hybrid_report else "",
                    "URL Analysis": hybrid_report[0].get("url_analysis", "") if hybrid_report else "",
                    "Mitre Attcks": hybrid_report[0].get("mitre_attcks", []) if hybrid_report else [],
                    "Classification Tags": hybrid_report[0].get("classification_tags", []) if hybrid_report else [],
                    "Tags": hybrid_report[0].get("tags", []) if hybrid_report else [],
                    "Detected Vendors": hybrid_report[0].get("detected_vendors", 0) if hybrid_report else 0,
                    "Detected URLs": len(hybrid_report[0].get("detected_urls", [])) if hybrid_report else 0,
                    "Stats": hybrid_report[0].get("stats", {}) if hybrid_report else {}
                }
            }
            data.append(row)
        
        if "VirusTotal" in reports:
            df_vt = pd.DataFrame([{
                "SHA1": d["Hash Value"],
                "Malicious Rating": f"{d['VirusTotal']['Malicious']}/{d['VirusTotal']['Malicious'] + d['VirusTotal']['Suspicious'] + d['VirusTotal']['Undetected'] + d['VirusTotal']['Harmless']}" if d['VirusTotal']['Malicious'] != 0 else "No matches found",
                "Tags": d["VirusTotal"]["Tags"],
                "Popular Threat Name": d["VirusTotal"]["Popular Threat Classification"],
                "Link": f"https://www.virustotal.com/gui/file/{d['Hash Value']}"
            } for d in data])
            
            st.write("VirusTotal Report:")
            st.write(df_vt)
        
        if "Hybrid-Analysis" in reports:
            df_hybrid = pd.DataFrame([{
                "Hash Value": d["Hash Value"], 
                "Threat Level": d["Hybrid-Analysis"].get("Threat Level", "") if "Hybrid-Analysis" in d else "",
                "Verdict": d["Hybrid-Analysis"].get("Verdict", "") if "Hybrid-Analysis" in d else "",
                "AV Detect": f"{d['Hybrid-Analysis'].get('AV Detect', 0)}/100" if "Hybrid-Analysis" in d else 0,
                "VX Family": d["Hybrid-Analysis"].get("VX Family", "") if "Hybrid-Analysis" in d else "",
                "Link": f"https://www.hybrid-analysis.com/sample/{d['Hash Value']}"
            } for d in data])
            
            st.write("Hybrid-Analysis Report:")
            st.write(df_hybrid)
with tab_domain:
    upload_file = st.file_uploader("Upload a txt file with domains separated by newlines", type=["txt"])
    if upload_file:
        domains = upload_file.read().decode("utf-8").splitlines()
    else:
        domains = st.text_input("Enter domains separated by commas:")

    reports = st.multiselect("Select Reports", ["VirusTotal"], default=["VirusTotal"])
    st.write("Please refrain from using VirusTotal if more than 4 Domains involved!")

    st.markdown("""
    <a href="#" data-toggle="tooltip" title="API Limitations: 
    VirusTotal: 4 requests per minute">API limitations</a>
    """, unsafe_allow_html=True)

    if st.button("Check Domain", key="check_domain"):
        if upload_file:
            domains_list = domains
        else:
            domains_list = [domain.strip() for domain in domains.split(",")]

        data = []
        for domain in domains_list:
            vt_report = None
            if "VirusTotal" in reports:
                vt_report = get_vt_report_domain(domain)
            row = {
                "Domain": domain,
                "VirusTotal": {
                    "Malicious": vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) if vt_report else "",
                    "Suspicious": vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", 0) if vt_report else "",
                    "Undetected": vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("undetected", 0) if vt_report else "",
                    "Harmless": vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("harmless", 0) if vt_report else "",
                }
            }
            data.append(row)

        if "VirusTotal" in reports:
            df_vt = pd.DataFrame([{
                "Domain": d["Domain"],
                "Malicious": f"{d['VirusTotal']['Malicious']}/94",
                "Undetected": d["VirusTotal"]["Undetected"],
                "Harmless": d["VirusTotal"]["Harmless"],
                "Suspicious": d["VirusTotal"]["Suspicious"],
                "Link": f"https://www.virustotal.com/gui/domain/{d['Domain']}"
            } for d in data if d["Domain"] is not None and d["Domain"] != ""])
            st.write("VirusTotal Report:")
            st.write(df_vt)

with tab_about:
    st.markdown("""
<a href="#" data-toggle="tooltip" title="Upcoming:
Upcoming Updates: Any.Run, URLhaus, MISP, CAPE, Malshare, Valhalla, Hashlookup">ChangeLog</a>
""", unsafe_allow_html=True)
    st.title("ChangeLog:")
    st.subheader("19/01/2025:")
    st.write("1. Change VirusTotal API from v2 to v3 for hashes")
    st.write("2. Improve table ranges for VirusTotal Hashes")
    st.write("3. Redundancy exfil across APIs")
    st.title("About:")
    st.write("This tool is designed to help you bulk check IP addresses and hashes for potential security threats.")
    st.write("It uses APIs from VirusTotal, AbuseIPDB, Who.Is and Hybrid-Analysis to gather information about the IP addresses and hashes you enter.")

    st.subheader("How to Use:")
    st.write("1. Enter IP addresses or hashes in the input field, separated by commas or newlines.")
    st.write("2. Select the reports you want to generate from the dropdown menu.")
    st.write("3. Click the 'Check IP' or 'Check Hash' button to generate the reports.")
    st.write("4. The reports will be displayed in a table format, with links to the original reports on the respective websites.")
    st.write("5. You may download the report in .csv format if required by clicking the download button on the top right of the report.")

    st.subheader("Limitations:")
    st.write("1. VirusTotal API: 4 requests per minute")
    st.write("2. AbuseIPDB API: 1000 requests per day")
    st.write("3. Hybrid-Analysis API: 1000 requests per day")
    st.write("4. Who.is API: No API limitations specified, but please refrain from making excessive requests.")

    st.subheader("Contact:")
    st.write("If you have any ideas, questions or concerns, please feel free to contact Mohammed Aman")
