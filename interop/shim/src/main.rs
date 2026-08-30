//! Subsumption verdicts from the tenuo reference implementation.
//!
//! Reads a JSON array of {id, parent, derived} on stdin, where `parent` and
//! `derived` are draft-01 §3.4 constraint objects, and writes a JSON array of
//! {id, verdict, detail} on stdout. Nothing else: this shim exists so the Go
//! harness can ask tenuo one question per case and diff the answer.
//!
//! # THE DIRECTION MAPPING — read before trusting any verdict
//!
//! The two APIs take their arguments in opposite orders AND opposite senses:
//!
//!   warden:  core.Subsumes(derived, parent) bool
//!            true  = derived is narrower-or-equal than parent = valid attenuation
//!
//!   tenuo:   parent.validate_attenuation(&child) -> Result<()>
//!            Ok(()) = child is narrower-or-equal than parent = valid attenuation
//!
//! So warden's FIRST argument is tenuo's ARGUMENT, and warden's SECOND argument
//! is tenuo's RECEIVER. The equivalence this harness asserts is:
//!
//!   core.Subsumes(d, p) == true   <=>   p.validate_attenuation(&d).is_ok()
//!
//! Get this backwards and every verdict inverts while still looking plausible,
//! because most of the corpus is symmetric-looking. The Go side gates the whole
//! run on a `direction-probe` category of cases whose verdict flips under swap;
//! if those do not come back exactly as expected, the run aborts rather than
//! reporting.
//!
//! # THE VALUE MAPPING — a deliberate choice, not an oversight
//!
//! tenuo's ConstraintValue distinguishes Integer(i64) from Float(f64) and
//! compares them with PartialEq, so Integer(1) != Float(1.0). draft-01 carries
//! constraints as JSON canonicalized per RFC 8785, where `1` and `1.0` are the
//! same value, and warden reads both as float64.
//!
//! Every JSON number here maps to ConstraintValue::Float, unconditionally. That
//! keeps the comparison a test of SUBSUMPTION LOGIC rather than of value-model
//! translation. The int/float hazard is real but it is a property of bridging
//! JSON to a CBOR-native value model, not a disagreement about §4.5 — it is
//! recorded in docs/ref/NOTES.md instead of being smuggled in as a finding here.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tenuo::constraints::{
    All, Any, Constraint, ConstraintValue, Contains, Exact, NotOneOf, OneOf, Range, Subset,
    Wildcard,
};

#[derive(Deserialize)]
struct Case {
    id: String,
    parent: serde_json::Value,
    derived: serde_json::Value,
}

#[derive(Serialize)]
struct Verdict {
    id: String,
    /// "permit" | "deny" | "unsupported"
    verdict: String,
    detail: String,
}

fn to_value(v: &serde_json::Value) -> Result<ConstraintValue, String> {
    use serde_json::Value as J;
    Ok(match v {
        J::String(s) => ConstraintValue::String(s.clone()),
        // See THE VALUE MAPPING above: always Float, never Integer.
        J::Number(n) => ConstraintValue::Float(
            n.as_f64().ok_or_else(|| format!("number {n} is not representable as f64"))?,
        ),
        J::Bool(b) => ConstraintValue::Boolean(*b),
        J::Array(a) => ConstraintValue::List(
            a.iter().map(to_value).collect::<Result<Vec<_>, _>>()?,
        ),
        J::Object(o) => {
            let mut m = BTreeMap::new();
            for (k, val) in o {
                m.insert(k.clone(), to_value(val)?);
            }
            ConstraintValue::Object(m)
        }
        J::Null => return Err("null is not a constraint value".into()),
    })
}

/// Map a draft-01 §3.4 constraint object onto a tenuo Constraint.
///
/// Struct literals rather than the `::new` constructors on purpose: tenuo's
/// OneOf::new and NotOneOf::new take strings only, which would silently drop
/// every numeric case in the corpus.
fn to_constraint(v: &serde_json::Value) -> Result<Constraint, String> {
    let o = v.as_object().ok_or("constraint is not a JSON object")?;
    let typ = o
        .get("constraint_type")
        .and_then(|t| t.as_str())
        .ok_or("constraint: missing or non-string constraint_type")?;

    let values = |key: &str| -> Result<Vec<ConstraintValue>, String> {
        o.get(key)
            .and_then(|x| x.as_array())
            .ok_or_else(|| format!("{typ}: {key} is missing or not an array"))?
            .iter()
            .map(to_value)
            .collect()
    };
    let clauses = || -> Result<Vec<Constraint>, String> {
        o.get("constraints")
            .and_then(|x| x.as_array())
            .ok_or_else(|| format!("{typ}: constraints is missing or not an array"))?
            .iter()
            .map(to_constraint)
            .collect()
    };

    Ok(match typ {
        "wildcard" => Constraint::Wildcard(Wildcard),
        "exact" => Constraint::Exact(Exact {
            value: to_value(o.get("value").ok_or("exact: missing value")?)?,
        }),
        "one_of" => Constraint::OneOf(OneOf { values: values("values")? }),
        "not_one_of" => Constraint::NotOneOf(NotOneOf { excluded: values("excluded")? }),
        "contains" => Constraint::Contains(Contains { required: values("required")? }),
        "subset" => Constraint::Subset(Subset { allowed: values("allowed")? }),
        "all" => Constraint::All(All { constraints: clauses()? }),
        "any" => Constraint::Any(Any { constraints: clauses()? }),
        "range" => {
            let num = |key: &str| -> Result<Option<f64>, String> {
                match o.get(key) {
                    None => Ok(None),
                    Some(x) => x
                        .as_f64()
                        .map(Some)
                        .ok_or_else(|| format!("range: {key} is not a number")),
                }
            };
            // §3.4: both inclusivity flags default to true when absent.
            let flag = |key: &str| -> Result<bool, String> {
                match o.get(key) {
                    None => Ok(true),
                    Some(x) => x
                        .as_bool()
                        .ok_or_else(|| format!("range: {key} is not a boolean")),
                }
            };
            Constraint::Range(Range {
                min: num("min")?,
                max: num("max")?,
                min_inclusive: flag("min_inclusive")?,
                max_inclusive: flag("max_inclusive")?,
            })
        }
        other => return Err(format!("constraint_type {other:?} has no tenuo equivalent")),
    })
}

fn main() {
    let cases: Vec<Case> = serde_json::from_reader(std::io::stdin().lock())
        .expect("shim: could not read the case array on stdin");

    let out: Vec<Verdict> = cases
        .iter()
        .map(|c| {
            let (parent, derived) = match (to_constraint(&c.parent), to_constraint(&c.derived)) {
                (Ok(p), Ok(d)) => (p, d),
                (Err(e), _) | (_, Err(e)) => {
                    return Verdict {
                        id: c.id.clone(),
                        verdict: "unsupported".into(),
                        detail: e,
                    }
                }
            };
            // The mapping, and the only place it is applied.
            match parent.validate_attenuation(&derived) {
                Ok(()) => Verdict { id: c.id.clone(), verdict: "permit".into(), detail: String::new() },
                Err(e) => Verdict { id: c.id.clone(), verdict: "deny".into(), detail: e.to_string() },
            }
        })
        .collect();

    serde_json::to_writer(std::io::stdout().lock(), &out).expect("shim: could not write verdicts");
}
