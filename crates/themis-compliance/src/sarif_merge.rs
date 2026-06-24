//! SARIF 2.1.0 merger for compliance evidence.
//!
//! Closes gap **G32** (Compliance SARIF). Merges SARIF output from
//! multiple scanners (CodeQL + apohara-compliance + future
//! Band-side scanners) into a single SARIF 2.1.0 artifact that the
//! Evidence Packet can attach as `properties[compliance_sarif]`
//! for DORA Art 17 + EU AI Act Art 12 traceability.
//!
//! Spec reference: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html>
//!
//! This module is intentionally a thin, deterministic merger —
//! no I/O, no LLM calls, no async. Callers feed `SarifReport`
//! values in, get a merged `SarifReport` or its JSON form out.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Top-level SARIF 2.1.0 document. We model only the fields we
/// emit or round-trip; SARIF allows additional `properties` we
/// preserve via the loose `serde_json::Value` passthrough on
/// `runs[].properties` when callers pass raw JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifReport {
    /// `$schema` URL. Defaults to the SARIF 2.1.0 JSON Schema
    /// from json.schemastore.org. Other valid values include
    /// the OASIS-published canonical URL.
    #[serde(rename = "$schema", default = "default_schema")]
    pub schema: String,
    /// SARIF version. Always `"2.1.0"` for these structs.
    pub version: String,
    /// One entry per scanner. Merging concatenates runs while
    /// preserving tool identity per run.
    pub runs: Vec<SarifRun>,
}

fn default_schema() -> String {
    SARIF_SCHEMA_URL.to_string()
}

/// Canonical SARIF 2.1.0 JSON Schema URL (json.schemastore.org
/// mirror). Other valid URLs exist (OASIS-published); we keep
/// this one because every CI SARIF consumer we integrate with
/// validates against the json.schemastore.org copy.
pub const SARIF_SCHEMA_URL: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// One scanner's run. Maps directly to `runs[]` entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifRun {
    /// Tool that produced this run. Required by the spec.
    pub tool: SarifTool,
    /// Results emitted by the tool. May be empty.
    #[serde(default)]
    pub results: Vec<SarifResult>,
    /// Optional free-form metadata bag. Used by the AIBOM
    /// (CycloneDX 1.6 `modelCard` + `datasets[]`) and other
    /// downstream consumers (DORA Art 17 control id, EU AI Act
    /// Art 12 traceability). SARIF 2.1.0 defines `properties`
    /// on every object; we expose it here so the AIBOM upload
    /// test (C-11 AC #6) round-trips cleanly through the
    /// merger.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub properties: Option<serde_json::Value>,
}

/// The scanner identity. `driver` is the only required field
/// per the spec; we expose it directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifTool {
    /// The scanner's driver metadata (name, version, info URI).
    pub driver: SarifDriver,
}

/// Driver metadata. `name` and `version` are required by the
/// SARIF 2.1.0 spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifDriver {
    /// Stable, machine-readable tool name (e.g. `"CodeQL"`).
    pub name: String,
    /// Semantic version of the tool.
    pub version: String,
    /// Optional URL with more information about the tool.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub information_uri: Option<String>,
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct SarifResult {
    /// Stable identifier of the rule that triggered the finding.
    /// Camel-cased per SARIF spec.
    #[allow(non_snake_case)]
    pub ruleId: String,
    /// Severity. One of `"none" | "note" | "warning" | "error"`.
    pub level: String,
    /// Human-readable message.
    pub message: SarifMessage,
    /// Locations the finding applies to. May be empty.
    #[serde(default)]
    pub locations: Vec<SarifLocation>,
}

/// The human-readable message. SARIF allows `text` + `markdown` + `id`; this merger only models `text`. Extra fields are preserved by passing JSON through for callers that need them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifMessage {
    /// Plain-text message body.
    pub text: String,
}

/// Where the finding lives. A result may have multiple
/// locations (multi-site findings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct SarifLocation {
    /// File + region triple. Camel-cased per SARIF spec.
    #[allow(non_snake_case)]
    pub physicalLocation: SarifPhysicalLocation,
}

/// The on-disk artifact + optional region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct SarifPhysicalLocation {
    /// URI of the artifact containing the finding. Camel-cased per SARIF spec.
    #[allow(non_snake_case)]
    pub artifactLocation: SarifArtifactLocation,
    /// Optional line range within the artifact.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub region: Option<SarifRegion>,
}

/// The URI for the artifact containing the finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    /// URI string (relative or absolute).
    pub uri: String,
}

/// A line range. Both bounds are 1-based and inclusive per the
/// SARIF spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct SarifRegion {
    /// 1-based inclusive start line. Camel-cased per SARIF spec.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[allow(non_snake_case)]
    pub startLine: Option<u32>,
    /// 1-based inclusive end line. Camel-cased per SARIF spec.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[allow(non_snake_case)]
    pub endLine: Option<u32>,
}

/// Failure modes for `from_json` / `merge` validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SarifMergeError {
    /// The input JSON was not a valid SARIF 2.1.0 document
    /// (missing `runs`, wrong `version`, etc.).
    #[error("invalid SARIF: {0}")]
    InvalidFormat(String),
}

/// Merge multiple SARIF reports into one. Concatenates all
/// `runs[]` from the inputs, preserves the schema/version of
/// the FIRST report, and drops empty reports without ceremony.
///
/// Determinism: output order matches input order. Callers that
/// care about stable ordering across merges should sort their
/// inputs before calling.
pub fn merge(reports: Vec<SarifReport>) -> SarifReport {
    let (first, rest) = match reports.split_first() {
        Some((f, r)) => (f, r),
        None => {
            return SarifReport {
                schema: SARIF_SCHEMA_URL.to_string(),
                version: "2.1.0".to_string(),
                runs: Vec::new(),
            };
        }
    };

    let mut runs: Vec<SarifRun> =
        Vec::with_capacity(first.runs.len() + rest.iter().map(|r| r.runs.len()).sum::<usize>());
    runs.extend(first.runs.iter().cloned());
    for report in rest {
        runs.extend(report.runs.iter().cloned());
    }

    SarifReport {
        schema: first.schema.clone(),
        version: first.version.clone(),
        runs,
    }
}

/// Serialize a `SarifReport` to a JSON value with the SARIF
/// 2.1.0 schema URL stamped on `$schema` if the caller left it
/// blank. We do NOT mutate a non-empty `$schema` — callers may
/// deliberately point at the OASIS canonical URL instead of
/// the json.schemastore.org mirror.
pub fn to_json(report: &SarifReport) -> serde_json::Value {
    let mut value = serde_json::to_value(report).expect("SarifReport is always serializable");
    if let Some(obj) = value.as_object_mut() {
        if obj
            .get("$schema")
            .and_then(|v| v.as_str())
            .map(str::is_empty)
            .unwrap_or(true)
        {
            obj.insert(
                "$schema".to_string(),
                serde_json::Value::String(SARIF_SCHEMA_URL.to_string()),
            );
        }
        obj.entry("version".to_string())
            .or_insert(serde_json::Value::String("2.1.0".to_string()));
    }
    value
}

/// Deserialize a SARIF JSON value into a `SarifReport` and
/// validate the spec-level invariants (version == 2.1.0,
/// `runs` is an array).
pub fn from_json(value: &serde_json::Value) -> Result<SarifReport, SarifMergeError> {
    let report: SarifReport = serde_json::from_value(value.clone())
        .map_err(|e| SarifMergeError::InvalidFormat(format!("serde: {e}")))?;

    if report.version != "2.1.0" {
        return Err(SarifMergeError::InvalidFormat(format!(
            "version must be 2.1.0, got {:?}",
            report.version
        )));
    }
    if report.schema.is_empty() {
        return Err(SarifMergeError::InvalidFormat(
            "$schema must not be empty".to_string(),
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture_run(name: &str, version: &str, findings: &[(&str, &str)]) -> SarifRun {
        SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: name.to_string(),
                    version: version.to_string(),
                    information_uri: None,
                },
            },
            results: findings
                .iter()
                .map(|(rule, uri)| SarifResult {
                    ruleId: (*rule).to_string(),
                    level: "warning".to_string(),
                    message: SarifMessage {
                        text: format!("finding {rule}"),
                    },
                    locations: vec![SarifLocation {
                        physicalLocation: SarifPhysicalLocation {
                            artifactLocation: SarifArtifactLocation {
                                uri: (*uri).to_string(),
                            },
                            region: None,
                        },
                    }],
                })
                .collect(),
            properties: None,
        }
    }

    #[test]
    fn merge_two_reports_keeps_all_runs() {
        let codeql = SarifReport {
            schema: SARIF_SCHEMA_URL.to_string(),
            version: "2.1.0".to_string(),
            runs: vec![fixture_run(
                "CodeQL",
                "2.20.0",
                &[("ql/injection", "src/a.rs")],
            )],
        };
        let themis = SarifReport {
            schema: SARIF_SCHEMA_URL.to_string(),
            version: "2.1.0".to_string(),
            runs: vec![fixture_run(
                "apohara-compliance",
                "1.0.0",
                &[("apohara/dora", "src/b.rs")],
            )],
        };
        let merged = merge(vec![codeql, themis]);
        assert_eq!(merged.runs.len(), 2);
        assert_eq!(merged.runs[0].tool.driver.name, "CodeQL");
        assert_eq!(merged.runs[1].tool.driver.name, "apohara-compliance");
        assert_eq!(merged.runs[1].results.len(), 1);
    }

    #[test]
    fn merge_preserves_first_schema() {
        let first = SarifReport {
            schema: "https://example.com/custom-schema.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![fixture_run("A", "1", &[])],
        };
        let second = SarifReport {
            schema: SARIF_SCHEMA_URL.to_string(),
            version: "2.1.0".to_string(),
            runs: vec![fixture_run("B", "1", &[])],
        };
        let merged = merge(vec![first, second]);
        assert_eq!(merged.schema, "https://example.com/custom-schema.json");
    }

    #[test]
    fn to_json_produces_valid_2_1_0_shape() {
        let report = SarifReport {
            schema: SARIF_SCHEMA_URL.to_string(),
            version: "2.1.0".to_string(),
            runs: vec![fixture_run("X", "0.1", &[("rule/x", "f.rs")])],
        };
        let json = to_json(&report);
        assert_eq!(json["version"], "2.1.0");
        assert_eq!(json["$schema"], SARIF_SCHEMA_URL);
        assert!(json["runs"].is_array());
        assert_eq!(json["runs"][0]["tool"]["driver"]["name"], "X");
        assert_eq!(json["runs"][0]["results"][0]["ruleId"], "rule/x");
    }

    #[test]
    fn from_json_roundtrips() {
        let original = SarifReport {
            schema: SARIF_SCHEMA_URL.to_string(),
            version: "2.1.0".to_string(),
            runs: vec![fixture_run("Y", "0.2", &[("rule/y", "g.rs")])],
        };
        let json = to_json(&original);
        let parsed = from_json(&json).expect("round-trip must succeed");
        assert_eq!(parsed, original);
    }

    #[test]
    fn from_json_rejects_wrong_version() {
        let bad = json!({
            "$schema": SARIF_SCHEMA_URL,
            "version": "2.0.0",
            "runs": []
        });
        let err = from_json(&bad).expect_err("2.0.0 must be rejected");
        assert!(matches!(err, SarifMergeError::InvalidFormat(_)));
    }

    #[test]
    fn merge_empty_input_returns_empty_report() {
        let merged = merge(Vec::new());
        assert!(merged.runs.is_empty());
        assert_eq!(merged.version, "2.1.0");
        assert_eq!(merged.schema, SARIF_SCHEMA_URL);
    }

    /// AC #6 / AIBOM upload test per the C-11 critic amendment.
    /// A CycloneDX 1.6 AIBOM with `modelCard` + `datasets[]`
    /// provenance must survive a SARIF merge without losing its
    /// `properties[name=ai_disclosure] = true` and
    /// `properties[name=model_card] = {datasets: [...]}` markers.
    /// The SARIF merger is structural — it concatenates runs —
    /// but the JSON shape must round-trip the properties bag
    /// when a caller wraps the AIBOM into a SARIF run's
    /// `properties` field via JSON passthrough.
    #[test]
    fn sarif_merge_preserves_aibom_model_card() {
        let aibom_payload = json!({
            "$schema": SARIF_SCHEMA_URL,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "apohara-aibom", "version": "1.6.0"}},
                    "results": [],
                    "properties": {
                        "ai_disclosure": true,
                        "model_card": {
                            "name": "apohara-compliance@1.0.0",
                            "datasets": [
                                {"id": "invoicenet-1k", "license": "CC-BY-4.0"},
                                {"id": "czech-bank-1k", "license": "CC-BY-4.0"}
                            ]
                        }
                    }
                }
            ]
        });
        let parsed = from_json(&aibom_payload).expect("AIBOM SARIF must parse");
        let merged = merge(vec![parsed.clone(), parsed.clone()]);
        let json = to_json(&merged);

        // Two runs survived the merge.
        assert_eq!(json["runs"].as_array().unwrap().len(), 2);

        // Each run retains the AI disclosure + model card with datasets.
        for run in json["runs"].as_array().unwrap() {
            assert_eq!(run["properties"]["ai_disclosure"], json!(true));
            assert_eq!(
                run["properties"]["model_card"]["name"],
                "apohara-compliance@1.0.0"
            );
            let datasets = run["properties"]["model_card"]["datasets"]
                .as_array()
                .unwrap();
            assert_eq!(datasets.len(), 2);
            assert_eq!(datasets[0]["id"], "invoicenet-1k");
            assert_eq!(datasets[1]["id"], "czech-bank-1k");
        }
    }
}
