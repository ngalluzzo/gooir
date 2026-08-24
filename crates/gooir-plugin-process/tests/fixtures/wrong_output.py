import json, sys
json.load(sys.stdin)
out = [{"fact_type": {"package": "not.asked", "name": "for", "version": "1.0.0"},
        "coverage": "complete", "payload": {}}]
json.dump({"protocol": "org.gooi.plugin/v1", "outputs": out}, sys.stdout)
