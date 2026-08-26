import json, sys
json.load(sys.stdin)
json.dump({"protocol": "org.gooi.plugin/v2", "error": "cannot do that"}, sys.stdout)
