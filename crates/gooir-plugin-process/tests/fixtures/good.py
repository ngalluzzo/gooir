import json, sys
r = json.load(sys.stdin)
out = [{"fact_type": r["capability"]["produces"][0], "coverage": "complete",
        "payload": {"ok": True}}]
json.dump({"protocol": "org.gooi.plugin/v1", "outputs": out}, sys.stdout)
