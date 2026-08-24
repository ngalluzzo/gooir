import json, sys
json.load(sys.stdin)
json.dump({"protocol": "org.gooi.plugin/v99", "outputs": []}, sys.stdout)
