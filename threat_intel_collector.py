

import requests
import json

url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

response = requests.get(url)

if response.status_code == 200:
    data = response.json()

    cleaned_data = []

    for entry in data:
        cleaned_entry = {
            "ip": entry.get("ip_address"),
            "port": entry.get("port"),
            "malware": entry.get("malware"),
            "timestamp": entry.get("first_seen")
        }
        cleaned_data.append(cleaned_entry)

    with open("cleaned_threat_intel.json", "w") as f:
        json.dump(cleaned_data, f, indent=4)

    print("Cleaned data saved:", len(cleaned_data), "entries")

else:
    print("Failed to retrieve data")
