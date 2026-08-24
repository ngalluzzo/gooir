import json, sys
json.load(sys.stdin)
json.dump({"protocol": "org.gooi.plugin/v1"}, sys.stdout)
