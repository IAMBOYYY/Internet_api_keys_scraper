import json
import os

import requests
from flask import Flask, jsonify, render_template

app = Flask(__name__)

RESULTS_URL = os.environ.get("RESULTS_JSON_URL", "")
LOCAL_RESULTS = os.path.join(os.path.dirname(__file__), "data", "results.json")


def load_results() -> dict:
    if RESULTS_URL:
        try:
            r = requests.get(RESULTS_URL, timeout=15)
            r.raise_for_status()
            return r.json()
        except Exception:
            pass

    if os.path.exists(LOCAL_RESULTS):
        with open(LOCAL_RESULTS, "r", encoding="utf-8") as f:
            return json.load(f)

    return {
        "generated_at": None,
        "stats": {"scanned_total": 0, "findings_total": 0, "verified_total": 0},
        "findings": [],
    }


@app.route("/")
def index():
    return render_template("index.html", data=load_results())


@app.route("/api/results")
def api_results():
    return jsonify(load_results())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
