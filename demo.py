import urllib.request, json

BASE = "https://blackbox-xray-177634575581.us-central1.run.app"
CID = "6d89d27f-9ed3-4ed8-bcc2-4b8143f7a82f"

resp = urllib.request.urlopen(BASE + f"/api/campaign/{CID}/status")
result = json.loads(resp.read().decode())
print(json.dumps(result, indent=2))
