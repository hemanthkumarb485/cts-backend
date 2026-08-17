# Backend Technical Flow Analysis

This backend is a stateless vulnerability ingestion pipeline for four scanner families: ZAP, Nuclei, OpenVAS, and Nmap. Each input is parsed into a raw record dictionary, normalized into the shared CanonicalFinding schema, then processed through deduplication, false-positive filters, threat intel enrichment, and risk scoring before returning a ScanSession payload.

## High-level architecture

The main execution path starts in [app/api/v1/endpoints/scan.py](app/api/v1/endpoints/scan.py), which accepts uploaded files and routes them into [app/services/pipeline.py](app/services/pipeline.py).

```mermaid
flowchart TD
    A[HTTP upload /scan/upload or /scan/process] --> B[scan.py: _read_file_content + file collection]
    B --> C[run_pipeline(files)]
    C --> D[tool-specific parser]
    D --> E[normalize_findings]
    E --> F[CanonicalFinding]
    F --> G[deduplicate]
    G --> H[apply_false_positive_rules]
    H --> I[filter_active]
    I --> J[enrich_findings]
    J --> K[score_all_findings]
    K --> L[ScanSession response / SSE stream]

    D --> D1[ZAP parser]
    D --> D2[Nuclei parser]
    D --> D3[OpenVAS parser]
    D --> D4[Nmap parser]
```

## 1. Entry points and file ingestion

### API layer

The upload endpoints are defined in [app/api/v1/endpoints/scan.py](app/api/v1/endpoints/scan.py):

- /scan/upload: returns streaming EventSourceResponse using the SSE pipeline
- /scan/process: returns the final ScanSession synchronously

These endpoints accept up to four optional uploads:

- zap_file + zap_format
- nuclei_file + nuclei_format
- openvas_file + openvas_format
- nmap_file + nmap_format

The endpoint builds a list of file objects like:

- tool
- fmt
- content
- filename
- criticality

This is the first important mapping step: model-specific upload input is converted into a generic internal shape before parsing.

### File extraction helpers

The same endpoint also handles non-plain text inputs:

- \_read_file_content: reads bytes and decodes text
- \_extract_pdf: extracts PDF text via PyMuPDF
- \_extract_html: extracts HTML text via BeautifulSoup

This means the scanner input may be plain XML/JSON/SARIF or a PDF/HTML wrapper that gets converted to text before parser dispatch.

---

## 2. Shared canonical model

All four scanners converge into the unified schema in [app/schemas/canonical.py](app/schemas/canonical.py).

CanonicalFinding contains:

- source_tool: ZAP / NUCLEI / OPENVAS / NMAP
- source_format: JSON / JSONL / XML / SARIF / MARKDOWN / NORMAL_TEXT / GREPABLE
- asset metadata: hostname, IP, domain, port, URL, path, protocol
- vulnerability identifiers: cve_id, cwe_id, wasc_id, nvt_oid
- severity fields: raw_severity, severity, confidence, cvss
- request/response metadata for web findings
- network metadata: port_state, service_method, qod, nvt_family
- threat intelligence: epss_score, kev flags, nvd description
- risk_score: final_score, priority_tier, scoring_method
- false_positive and deduplication metadata

This is the central contract that allows different raw scanner formats to be treated as one vulnerability model.

## 3. The common processing pipeline

The orchestrator is [app/services/pipeline.py](app/services/pipeline.py):

### run_pipeline(files)

For each uploaded file:

1. Detect tool name and format.
2. Select the parser from PARSER_MAP.
3. Call parser(content, fmt).
4. Run normalize_findings(tool, raw_records).
5. Set asset.criticality based on the per-session value.
6. Append findings to the session-wide all_findings list.
7. Collect processing_errors for any failed parser or normalization stage.

Then the pipeline executes these steps in order:

1. Deduplication
2. False positive filtering
3. Threat intel enrichment
4. Risk scoring
5. Return ScanSession

### run_pipeline_sse(files)

The SSE version is used for /scan/upload. It emits stage updates such as:

- start
- parsing
- normalization
- processing
- deduplication
- enrichment
- scoring
- complete

This provides progress monitoring while the same logic runs in a thread pool.

## Final JSON sent to UI

The backend emits a final SSE event for `/scan/upload` in this shape:

```json
{
  "stage": "complete",
  "percent": 100,
  "message": "Pipeline complete!",
  "elapsed_seconds": 3.42,
  "data": {
    "session_id": "b7a9d6c2-4d0f-4f80-9a63-1c3b7f7ebf11",
    "uploaded_files": ["zap_report.json", "nuclei.json"],
    "tools_detected": ["zap", "nuclei"],
    "total_raw_findings": 42,
    "total_after_dedup": 31,
    "total_after_fp_filter": 27,
    "total_scored": 19,
    "total_unscored": 8,
    "findings": [
      {
        "finding_id": "uuid-string",
        "raw_finding_id": "rule-123",
        "source_tool": "zap",
        "source_format": "json",
        "scan_date": "2026-08-17T12:00:00Z",
        "vulnerability_name": "Reflected XSS",
        "description": "Cross-site scripting vulnerability found in the target URL.",
        "impact": null,
        "solution": "Sanitize and encode input.",
        "references": ["https://example.com/docs"],
        "cve_id": null,
        "cve_ids": null,
        "cwe_id": "CWE-79",
        "wasc_id": null,
        "nvt_oid": null,
        "raw_severity": "High",
        "severity": "high",
        "confidence": "High",
        "cvss": {
          "base_score": 7.5,
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
          "version": "3.1",
          "severity_normalized": "high"
        },
        "asset": {
          "ip": null,
          "hostname": null,
          "domain": "example.com",
          "port": 443,
          "protocol": "https",
          "url": "https://example.com/login",
          "path": "/login",
          "service_name": null,
          "service_version": null,
          "criticality": "unknown"
        },
        "http_method": "GET",
        "parameter": null,
        "attack": null,
        "evidence": "<script>alert(1)</script>",
        "matcher_name": null,
        "http_request": {
          "method": "GET",
          "target": "https://example.com/login",
          "protocol": "https",
          "version": "1.1",
          "headers": {},
          "body": null
        },
        "http_response": {
          "status_code": 200,
          "reason": "OK",
          "headers": {},
          "body": null
        },
        "port_state": null,
        "service_method": null,
        "nvt_family": null,
        "qod": null,
        "solution_type": null,
        "tags": ["web", "xss"],
        "finding_type": "web",
        "is_systemic": false,
        "data_completeness": "full",
        "threat_intel": {
          "epss_score": 0.42,
          "epss_percentile": 0.81,
          "epss_date": null,
          "is_kev": false,
          "kev_date_added": null,
          "kev_due_date": null,
          "kev_ransomware_use": null,
          "nvd_description": null,
          "nvd_cvss_score": null,
          "nvd_cvss_severity": null,
          "has_public_exploit": false,
          "exploit_ids": null,
          "exploit_descriptions": null,
          "enrichment_attempted": true,
          "enrichment_errors": null
        },
        "risk_score": {
          "cvss_component": 75.0,
          "kev_component": 0.0,
          "epss_component": 42.0,
          "exploitdb_component": 0.0,
          "cwe_component": null,
          "base_score": 70.0,
          "criticality_multiplier": 1.0,
          "final_score": 70.0,
          "priority_tier": "P1",
          "scoring_method": "cve_based"
        },
        "deduplication": {
          "dedup_key": "sha256-hash",
          "dedup_method": "exact",
          "duplicate_of": null,
          "is_duplicate": false,
          "source_scanners": ["zap"],
          "corroboration_count": 1
        },
        "false_positive": {
          "fp_rules_applied": ["R007"],
          "fp_status": "active",
          "fp_reason": null,
          "ml_fp_probability": null
        },
        "raw_data": {}
      }
    ],
    "processing_errors": [],
    "processing_time_seconds": 3.42
  }
}
```

For the synchronous `/scan/process` API, the UI receives the same `ScanSession` object directly without the outer SSE wrapper.

---

## 4. Four scanner-specific parsing flows

### 4.1 ZAP flow

Responsible files:

- [app/services/parsers/zap_parser.py](app/services/parsers/zap_parser.py)
- [app/services/normalization.py](app/services/normalization.py)

#### Parser layer

The dispatcher is parse_zap(content, fmt).

It supports:

- SARIF: parse_zap_sarif
- XML: parse_zap_xml
- JSON: parse_zap_native_json

Auto-detection rules:

- if fmt == sarif -> SARIF parser
- if fmt == xml -> XML parser
- if fmt in json/native_json -> native JSON parser
- otherwise detect by content shape:
  - starts with < -> XML
  - JSON with runs -> SARIF
  - fallback -> native JSON

#### Raw record structure

Each parsed result becomes a dict with fields like:

- rule_id
- name
- risk_desc
- confidence
- description
- solution
- references
- cwe_id / wasc_id
- host / port / protocol / uri
- req_method / req_target / req_body / res_status
- evidence / attack / snippet

#### Normalization mapping

In normalize_zap(raw):

- raw_sev is extracted from risk_desc or level
- informational results are stripped by \_skip
- severity normalized via \_sev
- host and URL are mapped into AssetSchema
- http request/response sections are attached to HTTPRequestSchema and HTTPResponseSchema
- cwe_id and wasc_id are mapped to canonical identifiers
- deduplication metadata is created using \_dedup

#### ZAP-specific canonical behavior

ZAP findings are treated as web findings:

- asset.domain / asset.hostname / asset.url
- asset.path from URL
- http_method and evidence captured if present
- confidence retained for false-positive logic

---

### 4.2 Nuclei flow

Responsible files:

- [app/services/parsers/nuclei_parser.py](app/services/parsers/nuclei_parser.py)
- [app/services/normalization.py](app/services/normalization.py)

#### Parser layer

The dispatcher is parse_nuclei(content, fmt).

Supported formats:

- jsonl: parse_nuclei_jsonl
- json: parse_nuclei_json
- sarif: parse_nuclei_sarif
- markdown: parse_nuclei_markdown

Auto-detection:

- markdown if the content begins with #
- SARIF if JSON contains runs
- JSON array if JSON is a list
- otherwise JSONL line-by-line

#### Raw record structure

The parser builds records with fields such as:

- template_id
- name
- severity
- description / impact / solution
- references
- tags
- cve_ids / cwe_ids
- cvss_score / cvss_vector
- host / ip / port / matched_at
- matcher_name
- extracted_results

#### Normalization mapping

In normalize_nuclei(raw):

- severity is normalized from raw severity using CVSS-based fallback for numbers
- cve_ids are filtered and primary CVE is selected
- cwe_primary is normalized via \_cwe
- CVSS schema is created if a score exists
- host + matched_at is turned into AssetSchema
- evidence is built from extracted_results
- data_completeness is set to FULL or NO_CVE

Nuclei findings are also mapped into a web-asset model, but the host is often an IP or a matched-at URL, so the canonical model stores both hostname and url/path information.

---

### 4.3 OpenVAS flow

Responsible files:

- [app/services/parsers/openvas_parser.py](app/services/parsers/openvas_parser.py)
- [app/services/normalization.py](app/services/normalization.py)

#### Parser layer

OpenVAS is the simplest parser: parse_openvas(content, fmt="xml") calls parse_openvas_xml.

It reads XML result nodes and builds a host+port+NVT model from elements such as:

- host/ip
- result/nvt
- refs/ref with CVE / CWE / URL types
- qod/value
- nvt/family
- creation_time

#### Raw record structure

A parsed OpenVAS result includes:

- nvt_oid
- name
- threat
- description
- host_ip / hostname
- port / protocol
- cvss_score / cvss_vector
- cve_ids
- cwe_ids
- references
- solution / solution_type
- nvt_family
- qod
- scan_date

#### Normalization mapping

In normalize_openvas(raw):

- severity is derived from threat and CVSS when present
- CVEs and CWEs are normalized into canonical string IDs
- AssetSchema stores IP, hostname, port, protocol
- nvt_oid, nvt_family, qod, solution_type are preserved
- data_completeness is FULL if a CVE exists, otherwise NO_CVE

This is a network-oriented finding path; the canonical data model keeps network context rather than web HTTP context.

---

### 4.4 Nmap flow

Responsible files:

- [app/services/parsers/nmap_parser.py](app/services/nmap_parser.py)
- [app/services/normalization.py](app/services/normalization.py)

#### Parser layer

The dispatcher is parse_nmap(content, fmt).

Supported types:

- xml: parse_nmap_xml
- normal: parse_nmap_normal
- grepable: parse_nmap_grepable

Auto-detection rules:

- starts with < -> XML
- contains Ports: in the first 300 chars -> grepable
- otherwise normal text

#### Raw record structure

Nmap parsing yields either:

- vulnerability records when a script table exposes CVE data
- open-port entries when no CVE is associated with the port

Common fields:

- host_ip / hostname
- port / protocol
- port_state
- service_name / service_version
- service_method
- cve_ids
- cvss_score
- raw_finding_id
- script_id / vuln_url
- name / description

#### Normalization mapping

In normalize_nmap(raw):

- cve_ids are selected and normalized
- CVSS score becomes cvss.base_score when available
- severity defaults to LOW for unscored open-port findings
- asset fields are mapped to IP, hostname, port, protocol, service_name, service_version
- status and service metadata are preserved as port_state, service_method
- tags are set to ["open-port"] and finding_type is network
- data_completeness is NO_CVE when no CVE exists

Nmap is intentionally modeled as a mostly network/open-port signal; it does not need HTTP request/response context.

---

## 5. Common data transformations after parsing

Once each parser returns raw dicts, the common conversion point is [app/services/normalization.py](app/services/normalization.py):

### normalize_findings(tool, raw_records)

This dispatches to:

- normalize_zap
- normalize_nuclei
- normalize_openvas
- normalize_nmap

It performs these validations:

- strips informational/noise severities using \_skip
- normalizes severity names with \_sev
- extracts CVE and CWE IDs using \_cve and \_cwe
- converts to canonical asset, CVSS, and HTTP/network shapes
- drops records that are not actionable vulnerabilities

This is the real unification layer where all tool-specific input becomes a single object schema.

---

## 6. Deduplication flow

The deduplication logic is in [app/services/deduplication.py](app/services/deduplication.py).

### Strategy

1. Exact deduplication by compute_dedup_key
2. Fuzzy deduplication by vulnerability name + host similarity

The dedup key is computed inside [app/schemas/canonical.py](app/schemas/canonical.py):

- network: host + port + cve_id
- web: host/domain + path + cwe_id

This yields a SHA-256-based exact match key.

### Merge behavior

When duplicates are found:

- the primary finding is kept
- duplicate source_scanners are merged into primary.deduplication.source_scanners
- corroboration_count increments
- is_duplicate and duplicate_of are set on the duplicate item

This creates cross-scanner corroboration, which later drives false-positive and scoring logic.

---

## 7. False-positive and filtering flow

Rules are defined in [app/services/false_positive.py](app/services/false_positive.py).

### Rule set

- R001: low confidence + no evidence -> needs_review
- R002: informational severity -> suppressed
- R003: network finding with no CVE/CWE/evidence -> needs_review
- R004: OpenVAS QoD < 30 -> needs_review
- R005: 2+ scanners corroborate -> corroborated
- R006: ZAP false positive -> false_positive
- R007: confidence threshold logic -> review or active

Then filter_active keeps only findings with status:

- ACTIVE
- CORROBORATED
- NEEDS_REVIEW

This ensures pure noise and clearly false positives are filtered before threat enrichment.

---

## 8. Threat intelligence enrichment flow

This logic is in [app/services/threat_intel.py](app/services/threat_intel.py).

For each finding with a CVE:

- fetch EPSS batch values
- fetch NVD details in parallel
- check KEV database
- check Exploit-DB matches
- attach ThreatIntelSchema to the finding

Important implementation details:

- NVD calls are parallelized using ThreadPoolExecutor
- failures and missing data are handled gracefully
- no internet or unreachable services result in fallback values rather than blocking

The enriched fields include:

- epss_score / epss_percentile
- is_kev / kev_date_added / due_date
- nvd_description / nvd_cvss_score
- has_public_exploit / exploit_ids / exploit_descriptions
- enrichment_errors

This is the data source used later by risk scoring.

---

## 9. Risk scoring flow

The scoring engine is in [app/services/risk_engine.py](app/services/risk_engine.py).

The logic is hierarchical:

### Tier A: CVE-based

Used when finding.cve_id exists.

Formula:

- CVSS x 0.40
- KEV x 0.25
- EPSS x 0.20
- ExploitDB x 0.15

Then it applies asset criticality multiplier:

- production = 1.2
- staging = 1.0
- development = 0.8
- unknown = 1.0

### Tier B: CWE-based fallback

Used when a finding does not have a CVE but has a CWE or a non-informational severity.

Formula:

- severity x 0.55
- MITRE Top 25 CWE rank x 0.30
- ExploitDB CWE score x 0.15

### Tier C: Unscored

Used for bare open ports or unclassified results with no CVE and no CWE.

The final result is stored in RiskScoreSchema with:

- final_score
- priority_tier
- scoring_method

---

## 10. Final output shape

At the end of processing, [app/services/pipeline.py](app/services/pipeline.py) returns a ScanSession from [app/schemas/canonical.py](app/schemas/canonical.py):

- session_id
- uploaded_files
- tools_detected
- total_raw_findings
- total_after_dedup
- total_after_fp_filter
- total_scored / total_unscored
- findings
- processing_errors
- processing_time_seconds

The frontend receives either:

- a final JSON body from /scan/process
- or a streaming SSE event sequence from /scan/upload

---

## 11. End-to-end flow summary

The complete data path is:

1. Upload file(s) from scanner output
2. HTTP endpoint reads and validates file content
3. Parser dispatches by tool and format
4. Raw parser dicts are produced
5. Normalization maps to CanonicalFinding
6. Exact + fuzzy deduplication merges duplicates
7. False-positive rules reduce noise
8. Threat intel enriches CVE records
9. Risk scoring assigns severity and priority
10. Final ScanSession is returned to the client

This design gives the backend a single, consistent vulnerability model even though the four input sources are structurally very different.
