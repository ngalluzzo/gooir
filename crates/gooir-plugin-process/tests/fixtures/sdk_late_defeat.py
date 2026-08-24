import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../../../sdk/python"))
import gooir

def run(ctx):
    ctx.input("test.fact/source@1.0.0")
    ctx.produce("test.fact/produced@1.0.0", {"ok": True})
    # Recorded *after* the output. A provider must not be able to bank
    # completeness before admitting what it lost.
    ctx.defeat("authority_cannot_express", "n", "no target domain")

gooir.run(run, defeater_set="test.defeaters@1.0.0")
