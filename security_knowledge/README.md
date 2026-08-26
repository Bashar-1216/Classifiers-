# Security Knowledge Bundle

This directory is the canonical source for tunable security data. Algorithms remain in
`classifier/` and `risk_engine/`; threat signatures, lexicons, exclusions, contextual terms,
DLP candidate patterns, and semantic anchors live here.

## Ownership

| Data | Location |
|---|---|
| Deterministic ingress rules | `ingress/` |
| Adversarial and benign lexical corpora | `lexical/` |
| False-positive adjudication patterns | `adjudication/` |
| Multi-turn probing and execution terms | `context/` |
| DLP candidate patterns | `dlp/` |
| Semantic reference anchors | `semantic/` |

`manifest.yaml` declares required sources and supplies the bundle version. The loader validates
required files, duplicate identifiers, regular-expression syntax, path traversal, and file
structure before the classifier starts. Production changes should be reviewed and tested as one
versioned bundle; runtime hot reload is intentionally not enabled.
