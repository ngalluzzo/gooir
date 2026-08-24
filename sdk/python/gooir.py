"""Writing a GOOIR capability provider in Python.

A provider reads one `org.gooi.plugin/v1` request and writes one response.
Everything around the transformation — checking the protocol, finding the input
by fact type, unwrapping its envelope, deciding coverage, framing the reply — is
the same every time.

The one rule this enforces: **coverage is derived, never declared.** A provider
that could call its own output complete would be able to claim completeness it
did not earn, which is the single thing a defeasible result exists to prevent.
Record what you could not carry and the coverage follows.

    import gooir

    def lower(ctx):
        model = ctx.input("org.gooi.semantics.data_model/model@1.0.0")
        for entity in model["entities"]:
            ...
            ctx.defeat("authority_cannot_express", entity["name"], "no target domain")
        ctx.produce("org.gooi.artifact.typescript/model_types@0.1.0", {"source": text})

    gooir.run(lower, defeater_set="org.gooi.plugin.typescript_types/defeaters@1")
"""

import json
import sys

PROTOCOL = "org.gooi.plugin/v1"

#: The defeat kinds the kernel understands. Each implies a different action for
#: whoever reads the result, so they are not interchangeable.
KINDS = (
    "not_looked",
    "looked_and_blocked",
    "subject_unresolvable",
    "out_of_scope",
    "authority_cannot_express",
)


class ProviderError(Exception):
    """Something this provider cannot do. Reported, never raised at the host."""


class Context:
    """One invocation: its inputs, what was lost, and what it produced."""

    def __init__(self, request, defeater_set):
        self._request = request
        self._defeater_set = defeater_set
        self._defeats = []
        self._outputs = []

    def input(self, fact_type):
        """The payload of one declared input, by exact fact identity.

        A defeasible envelope is unwrapped, because a provider wants the value,
        not its provenance.
        """
        for candidate in self._request.get("inputs") or []:
            declared = candidate.get("fact_type") or {}
            identity = "{}/{}@{}".format(
                declared.get("package"), declared.get("name"), declared.get("version")
            )
            if identity != fact_type:
                continue
            payload = candidate.get("payload")
            if isinstance(payload, dict) and "value" in payload and "defeater_set" in payload:
                return payload["value"]
            return payload
        raise ProviderError("input {} is missing".format(fact_type))

    def defeat(self, kind, subject, reason):
        """Record something this provider could not establish or carry."""
        if kind not in KINDS:
            raise ProviderError(
                "unknown defeat kind {!r}; expected one of {}".format(kind, ", ".join(KINDS))
            )
        self._defeats.append({"kind": kind, "subject": str(subject), "reason": str(reason)})

    @property
    def defeats(self):
        return list(self._defeats)

    def produce(self, fact_type, value):
        """Publish one output. Its coverage comes from the recorded defeats."""
        package, rest = fact_type.split("/", 1)
        name, version = rest.split("@", 1)
        self._outputs.append(
            {
                "fact_type": {"package": package, "name": name, "version": version},
                "coverage": "complete" if not self._defeats else "partial",
                "payload": {
                    "value": value,
                    "defeater_set": self._defeater_set,
                    "defeats": list(self._defeats),
                },
            }
        )

    def _response(self):
        if not self._outputs:
            raise ProviderError("the provider produced nothing and reported no failure")
        # Defeats recorded after a produce still apply: coverage is a property of
        # the whole invocation, not of the moment an output was appended.
        for output in self._outputs:
            output["coverage"] = "complete" if not self._defeats else "partial"
            output["payload"]["defeats"] = list(self._defeats)
        return {"protocol": PROTOCOL, "outputs": self._outputs}


def run(handler, defeater_set, stdin=None, stdout=None):
    """Reads a request, runs `handler(ctx)`, writes a response.

    A failure is reported over the wire rather than as a crash, so the host sees
    a provider that said no rather than a process that died.
    """
    source = stdin or sys.stdin
    sink = stdout or sys.stdout
    try:
        request = json.load(source)
    except Exception as error:  # noqa: BLE001 - reported, not raised
        json.dump({"protocol": PROTOCOL, "error": "request was not valid JSON: {}".format(error)}, sink)
        return
    if request.get("protocol") != PROTOCOL:
        json.dump(
            {"protocol": PROTOCOL, "error": "unexpected protocol {!r}".format(request.get("protocol"))},
            sink,
        )
        return

    context = Context(request, defeater_set)
    try:
        handler(context)
        response = context._response()
    except ProviderError as error:
        response = {"protocol": PROTOCOL, "error": str(error)}
    except Exception as error:  # noqa: BLE001 - a provider fault is still an answer
        response = {"protocol": PROTOCOL, "error": "provider failed: {}".format(error)}
    json.dump(response, sink)
