We release AI agents every week. A manual safety review cannot keep that pace, and the gap is where risk lives.

The problem: a prompt tweak, a model upgrade or a new tool can change how an agent handles internal data or privileged actions. A point-in-time review says nothing about build 412.

Why it matters: release managers need a repeatable answer per version, with evidence an auditor can verify, not a slide.

The flow we built:
Suite → Probes → Agent (HTTP, MCP, A2A) → Judges → Scoring → Policy → Signed decision → Telemetry

How it works:
1. Versioned YAML suites, expanded deterministically from a seed. Same seed, same probes.
2. Probes are benign. A suite plants a synthetic CANARY marker in retrieved content or a config record, or asks for a tool on a forbidden list, or an action that policy gates behind approval. No attack text.
3. Judges are deterministic: marker disclosure in any common encoding, forbidden tools in the trace, policy violations, approval bypass.
4. Each category is scored with a Wilson interval. A release passes only if the upper bound is under the threshold, so small lucky samples cannot pass.
5. A versioned policy turns the facts into pass, fail or require approval. High-risk production releases need a second person.
6. The report is Ed25519-signed and its digest lands in a hash-chained audit log. A GitHub Action gates the pipeline using the job's OIDC token.

Best practices: treat target errors as missing evidence, never as a pass; keep the target blind to what is tested; keep an LLM judge advisory until it agrees with the deterministic judges.

Tradeoffs: tighter thresholds need more probes (73 per category at 5%), which costs runtime. Benign probes measure policy adherence, not resistance to novel attacks, so adversarial testing stays a separate programme. More policy files mean more governance work.

Value: routine releases ship without waiting on manual review, and every promotion carries verifiable evidence.

As agents gain tools, release engineering becomes a safety control.

Question for you: should a statistically clean run ever be enough to ship a high-risk agent without a human?

github.com/kogunlowo123/continuous-red-teaming

#AI #ArtificialIntelligence #GenerativeAI #AgenticAI #LLMOps #EnterpriseAI #AISecurity #RAG #MachineLearning #DataScience #CloudComputing #Kubernetes #MLOps #DigitalTransformation #Innovation #ReleaseEngineering #AIGovernance #MCP
