import re
import json
import csv
import os
from collections import defaultdict

# Fayl və qovluq adları
log_file = "access_log.txt"
html_file = "threat_feed.html"
results_dir = "results"

# Nəticə qovluğunu yaratmaq
if not os.path.exists(results_dir):
    os.makedirs(results_dir)

# URL və status kodlarını çıxarmaq üçün regex
log_pattern = re.compile(r'(http[s]?://[^\s]+) HTTP/1.1" (\d+)')
url_status_count = defaultdict(int)
log_data = []

# Access log faylını oxuyub məlumat çıxarmaq
with open(log_file, "r") as f:
    for line in f:
        match = log_pattern.search(line)
        if match:
            url, status = match.groups()
            log_data.append({"URL": url, "Status": status})
            if status == "404":
                url_status_count[url] += 1

# URL və status kodlarını txt faylına yazmaq
url_status_report_file = os.path.join(results_dir, "url_status_report.txt")
with open(url_status_report_file, "w") as f:
    for entry in log_data:
        f.write(f"{entry['URL']} - {entry['Status']}\n")

# 404 status kodu olan URL-ləri CSV faylına yazmaq
malware_candidates_file = os.path.join(results_dir, "malware_candidates.csv")
with open(malware_candidates_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["URL", "404 Count"])
    for url, count in url_status_count.items():
        writer.writerow([url, count])

# Qara siyahıya salınmış domenləri HTML faylından çıxarmaq
blacklisted_domains = []
with open(html_file, "r") as f:
    for line in f:
        match = re.search(r'<li>(.*?)</li>', line)
        if match:
            blacklisted_domains.append(match.group(1))

# Jurnal faylındakı URL-ləri qara siyahı ilə müqayisə etmək
alert_data = []
for url, count in url_status_count.items():
    for domain in blacklisted_domains:
        if domain in url:
            alert_data.append({"URL": url, "Domain": domain, "404 Count": count})

# Uyğun domenləri JSON faylına yazmaq
alert_file = os.path.join(results_dir, "alert.json")
with open(alert_file, "w") as f:
    json.dump(alert_data, f, indent=4)

# Ümumi xülasə hesabatı yaratmaq
summary_report = {
    "Total URLs": len(log_data),
    "Total 404 URLs": len(url_status_count),
    "Blacklisted Matches": len(alert_data),
    "Blacklisted Domains": blacklisted_domains
}

summary_report_file = os.path.join(results_dir, "summary_report.json")
with open(summary_report_file, "w") as f:
    json.dump(summary_report, f, indent=4)

print("Skript uğurla icra olundu. Nəticələr 'results' qovluğunda saxlanıldı.")
