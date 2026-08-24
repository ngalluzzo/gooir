import json, sys
json.load(sys.stdin)
json.dump({"protocol": "org.gooi.plugin/v1", "error": "cannot do that"}, sys.stdout)
