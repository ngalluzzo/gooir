import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../../../sdk/python"))
import gooir

def run(ctx):
    n = ctx.input("test.fact/source@1.0.0")["n"]
    ctx.produce("test.fact/produced@1.0.0", {"doubled": n * 2})

gooir.run(run, defeater_set="test.defeaters@1.0.0")
