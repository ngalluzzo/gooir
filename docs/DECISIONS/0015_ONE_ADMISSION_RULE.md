# 0015 — One admission rule

Status: complete

## What the two systems turned out to be

`gooir doctor` reported 9 of 9 providers unadmitted, and
[0014](0014_ONE_EXACT_IDENTITY.md) predicted the remaining half of the split
kernel was a duplicated trust path. Reading both first showed that prediction
was wrong in an important way. They are **sequential stages, not duplicates**:

| | [0002](0002_EVIDENCE_TRUST_POLICY.md) `EvidenceTrustPolicy` | capability `verify_and_admit` |
| --- | --- | --- |
| what it handles | an attestation that *arrived* with a claim | an attestation it *produces* by running a verifier |
| verification | none — explicitly the host's job, out of band | runs the suite in process |
| independence | not modeled | enforced: verifier ≠ provider by identity **and** digest |
| host policy | default-deny, binds one exact operation and claim | **absent** |

So there was nothing to merge. There was something missing.

## The hole

The capability path went straight from "an independent-looking verifier passed"
to "these facts are admitted." Any caller able to supply a verifier that merely
*differs* from the provider could mint admitted facts.

That is precisely the laundering hole 0002 closed, reopened in the newer
lineage. Its rationale applies verbatim: *"Trusting an authority or suite name
alone has the same flaw because no admitted result identity is required."*
An attestation produced in-process is no more self-certifying than one that
arrived over a wire.

## The fix

`AdmissionPolicy` is default-deny and separate from the conformance run. A host
records exact attester bindings — identity, suite, and implementation digest
together — having established that verifier's authority itself.

Facts now require **two independent conditions**: the attester passed, *and*
this host admits that attester. `verify_and_admit` reports which one failed:

```rust
pub enum FactsWithheld {
    ConformanceFailed,      // the attester reported a failing check
    AttesterNotAdmitted,    // it passed, and this host does not accept it
}
```

The conformance result is produced either way, which preserves 0002's central
distinction: a result records what an attester *reported*; whether it counts is
a separate decision. A host can therefore inspect an unadmitted verifier's
output before deciding to admit it.

Independence is still checked **before** policy, so a provider attesting its
own candidate fails as `VerifierNotIndependent` rather than as a policy miss.
The two rejections mean different things and should not be confused.

Binding the implementation digest matters: admitting an identity alone would let
a different build inherit the decision. A test covers exactly that case.

## What the doctor says now

The old wording — *"every registered provider is unadmitted, registration is
not conformance"* — was a caveat. It is now a measurement:

```
admission
  0 attester(s) admitted by this host
  9 provider(s) whose outputs are not admissible yet
  -> no produced fact can become admitted, whatever a verifier reports
```

`diagnose_with_policy` takes the host's policy; `diagnose` defaults to an empty
one, which is the honest default for a host that has not stated its position.

## Deliberately not done

`gooir_core::ConformanceEvidence` is the transport shape for a conformance
result crossing a process boundary. Sharing it with the capability path would
let the two worlds exchange results — but **no result crosses that boundary
today**, because 0011 leaves providers in-process. Unifying the transport now
would be building for an absent consumer, which is the discipline
[0003](0003_LIFT_FAMILIES.md) established when it declined to extract a seam
with one member.

The seam is named here so it is a decision rather than an oversight. It becomes
real work when a provider is invoked out of process.

## State

283 tests, clippy and fmt clean. The live Fleetd candidate fixture still admits
end to end, now through a stated policy.
