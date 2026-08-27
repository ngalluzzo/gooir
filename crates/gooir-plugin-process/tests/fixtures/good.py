import json, sys
r = json.load(sys.stdin)
out = [{"fact_type": r["capability"]["output_ports"][0]["value_kind"], "coverage": "complete",
        "payload": {"ok": True}}]
json.dump({"protocol": "org.gooi.plugin/v2", "outputs": out}, sys.stdout)
