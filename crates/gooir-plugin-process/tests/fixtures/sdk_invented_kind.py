import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../../../sdk/python"))
import gooir

def run(ctx):
    ctx.defeat("probably_fine", "n", "a kind the kernel does not know")
    ctx.produce("test.fact/produced@1.0.0", {"ok": True})

gooir.run(run, defeater_set="test.defeaters@1.0.0")
