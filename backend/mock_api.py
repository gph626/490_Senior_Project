from flask import Flask, jsonify, request

app = Flask(__name__)

# Mock configuration data for testing
MOCK_CONFIG = {
    "org_id": 123,
    "crawl_interval_minutes": 10,
    "keywords": ["company.org", "example.com", "password", "ssn"],
    "assets": {
        "domains": ["company.org", "example.com"],
        "emails": ["admin@company.org"]
    },
    "sources": {
        "pastebin": {"enabled": True, "limit": 5},
        "tor": {"enabled": True},
        "i2p": {"enabled": True, "urls": ["http://identiguy.i2p"]},
        "freenet": {"enabled": True, "urls": ["http://127.0.0.1:8888/"]},
        "github": {"enabled": True}
    }
}

@app.route("/v1/config/org/<int:org_id>", methods=["GET"])
def get_org_config(org_id):
    print(f"Received config request for org_id={org_id}")
    return jsonify(MOCK_CONFIG)

@app.route("/v1/events", methods=["POST"])
def receive_event():
    data = request.get_json()
    print("\n=== Received Event ===")
    print(data)
    return jsonify({"status": "ok"}), 200

@app.route("/health", methods=["GET"])
def health_check():
    return "OK", 200

# Print all routes AFTER all routes have been defined
print("=== Registered routes ===")
for rule in app.url_map.iter_rules():
    print(rule)

if __name__ == "__main__":
    app.run(debug=True)
