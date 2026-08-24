//! Cross-authority convergence: does the neutral waist represent two unlike
//! authorities well enough that they agree about the same system?
//!
//! This is the Phase 0 falsifier. It is deliberately not tuned to pass. Any
//! divergence it reports is either a defect in the waist, a gap in a lifter, or
//! a real difference in what the two authorities are able to observe -- and
//! naming which is the point of running it.

use semantics_data_model_v1::{DataModel, FieldShape, normalize};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    OnlyLeft,
    OnlyRight,
}

#[derive(Clone, Debug)]
pub enum Divergence {
    Entity {
        side: Side,
        entity: String,
    },
    Field {
        side: Side,
        entity: String,
        field: String,
    },
    Attribute {
        entity: String,
        field: String,
        attribute: &'static str,
        left: String,
        right: String,
    },
    Relation {
        side: Side,
        from: String,
        to: String,
    },
    UniqueSet {
        side: Side,
        entity: String,
        fields: Vec<String>,
    },
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub shared_entities: usize,
    pub shared_fields: usize,
    pub compared_attributes: usize,
    /// Attribute pairs where at least one authority reported `Unknown`. These
    /// are not divergences: the absence of information is already recorded as a
    /// defeat by the lifter that could not see it. Counting them as
    /// disagreement would double-report the same gap.
    pub authority_limited: usize,
    pub divergences: Vec<Divergence>,
}

impl Report {
    pub fn entity_divergences(&self) -> usize {
        self.divergences
            .iter()
            .filter(|d| matches!(d, Divergence::Entity { .. }))
            .count()
    }
    pub fn field_divergences(&self) -> usize {
        self.divergences
            .iter()
            .filter(|d| matches!(d, Divergence::Field { .. }))
            .count()
    }
    pub fn attribute_divergences(&self) -> usize {
        self.divergences
            .iter()
            .filter(|d| matches!(d, Divergence::Attribute { .. }))
            .count()
    }
    pub fn unique_set_divergences(&self) -> usize {
        self.divergences
            .iter()
            .filter(|d| matches!(d, Divergence::UniqueSet { .. }))
            .count()
    }
    pub fn relation_divergences(&self) -> usize {
        self.divergences
            .iter()
            .filter(|d| matches!(d, Divergence::Relation { .. }))
            .count()
    }
    /// Share of compared field attributes that agreed.
    pub fn attribute_agreement(&self) -> f64 {
        if self.compared_attributes == 0 {
            return 1.0;
        }
        1.0 - (self.attribute_divergences() as f64 / self.compared_attributes as f64)
    }
}

fn attrs(f: &FieldShape) -> [(&'static str, String); 6] {
    [
        ("type", format!("{:?}", f.ty)),
        ("nullable", format!("{:?}", f.nullable)),
        ("list", f.list.to_string()),
        ("identity", f.identity.to_string()),
        ("unique", f.unique.to_string()),
        ("default", format!("{:?}", f.default)),
    ]
}

pub fn compare(left: &DataModel, right: &DataModel) -> Report {
    let mut r = Report::default();

    for e in &left.entities {
        if right.entity(&e.name).is_none() {
            r.divergences.push(Divergence::Entity {
                side: Side::OnlyLeft,
                entity: e.name.clone(),
            });
        }
    }
    for e in &right.entities {
        if left.entity(&e.name).is_none() {
            r.divergences.push(Divergence::Entity {
                side: Side::OnlyRight,
                entity: e.name.clone(),
            });
        }
    }

    for le in &left.entities {
        let Some(re) = right.entity(&le.name) else {
            continue;
        };
        r.shared_entities += 1;
        for lf in &le.fields {
            match re.field(&lf.name) {
                None => r.divergences.push(Divergence::Field {
                    side: Side::OnlyLeft,
                    entity: le.name.clone(),
                    field: lf.name.clone(),
                }),
                Some(rf) => {
                    r.shared_fields += 1;
                    for ((name, lv), (_, rv)) in attrs(lf).into_iter().zip(attrs(rf)) {
                        if lv.contains("Unknown") || rv.contains("Unknown") {
                            r.authority_limited += 1;
                            continue;
                        }
                        r.compared_attributes += 1;
                        if lv != rv {
                            r.divergences.push(Divergence::Attribute {
                                entity: le.name.clone(),
                                field: lf.name.clone(),
                                attribute: name,
                                left: lv,
                                right: rv,
                            });
                        }
                    }
                }
            }
        }
        let norm_set = |v: &Vec<String>| {
            let mut n: Vec<String> = v.iter().map(|x| normalize(x)).collect();
            n.sort();
            n
        };
        let lsets: Vec<Vec<String>> = le.unique_sets.iter().map(norm_set).collect();
        let rsets: Vec<Vec<String>> = re.unique_sets.iter().map(norm_set).collect();
        for (i, k) in lsets.iter().enumerate() {
            if !rsets.contains(k) {
                r.divergences.push(Divergence::UniqueSet {
                    side: Side::OnlyLeft,
                    entity: le.name.clone(),
                    fields: le.unique_sets[i].clone(),
                });
            }
        }
        for (i, k) in rsets.iter().enumerate() {
            if !lsets.contains(k) {
                r.divergences.push(Divergence::UniqueSet {
                    side: Side::OnlyRight,
                    entity: le.name.clone(),
                    fields: re.unique_sets[i].clone(),
                });
            }
        }
        for rf in &re.fields {
            if le.field(&rf.name).is_none() {
                r.divergences.push(Divergence::Field {
                    side: Side::OnlyRight,
                    entity: le.name.clone(),
                    field: rf.name.clone(),
                });
            }
        }
    }

    // The carrying fields are part of a relation's identity. Comparing only the
    // endpoints would let a relation that names a nonexistent field pass.
    let key = |e: &semantics_data_model_v1::RelationEdge| {
        let mut f: Vec<String> = e.from_fields.iter().map(|x| normalize(x)).collect();
        f.sort();
        (normalize(&e.from_entity), normalize(&e.to_entity), f)
    };
    let lrel: Vec<_> = left.relations.iter().map(key).collect();
    let rrel: Vec<_> = right.relations.iter().map(key).collect();
    for (i, k) in lrel.iter().enumerate() {
        if !rrel.contains(k) {
            r.divergences.push(Divergence::Relation {
                side: Side::OnlyLeft,
                from: left.relations[i].from_entity.clone(),
                to: left.relations[i].to_entity.clone(),
            });
        }
    }
    for (i, k) in rrel.iter().enumerate() {
        if !lrel.contains(k) {
            r.divergences.push(Divergence::Relation {
                side: Side::OnlyRight,
                from: right.relations[i].from_entity.clone(),
                to: right.relations[i].to_entity.clone(),
            });
        }
    }

    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use semantics_data_model_v1::{EntityShape, FieldType, ScalarType};

    fn model(entity: &str, field: &str, ty: ScalarType) -> DataModel {
        DataModel {
            entities: vec![EntityShape {
                unique_sets: Vec::new(),
                name: entity.to_owned(),
                fields: vec![FieldShape {
                    name: field.to_owned(),
                    ty: FieldType::Scalar(ty),
                    nullable: semantics_data_model_v1::Presence::Required,
                    list: false,
                    identity: false,
                    unique: false,
                    default: semantics_data_model_v1::DefaultOrigin::None,
                }],
            }],
            relations: Vec::new(),
        }
    }

    #[test]
    fn models_differing_only_in_case_and_separators_converge() {
        let a = model("UserAccount", "emailVerified", ScalarType::Boolean);
        let b = model("user_account", "email_verified", ScalarType::Boolean);
        let r = compare(&a, &b);
        assert!(r.divergences.is_empty(), "{:?}", r.divergences);
        assert_eq!(r.shared_entities, 1);
    }

    #[test]
    fn a_pluralized_name_is_not_treated_as_the_same_entity() {
        // Matching `User` to `users` would require inventing a stemming rule.
        // Authorities that disagree on pluralization must say so via @@map.
        let a = model("User", "email", ScalarType::Text);
        let b = model("users", "email", ScalarType::Text);
        let r = compare(&a, &b);
        assert_eq!(r.entity_divergences(), 2);
    }

    #[test]
    fn a_comparison_against_unknown_is_not_a_divergence() {
        use semantics_data_model_v1::DefaultOrigin;
        let mut a = model("User", "id", ScalarType::Text);
        let mut b = model("User", "id", ScalarType::Text);
        a.entities[0].fields[0].default = DefaultOrigin::Application;
        b.entities[0].fields[0].default = DefaultOrigin::Unknown;
        let r = compare(&a, &b);
        assert_eq!(r.attribute_divergences(), 0);
        assert_eq!(r.authority_limited, 1);
    }

    #[test]
    fn a_type_disagreement_is_reported_not_smoothed() {
        let a = model("User", "id", ScalarType::Text);
        let b = model("User", "id", ScalarType::Uuid);
        let r = compare(&a, &b);
        assert_eq!(r.attribute_divergences(), 1);
        assert!(r.attribute_agreement() < 1.0);
    }

    #[test]
    fn entities_present_on_one_side_only_are_reported_per_side() {
        let a = model("User", "id", ScalarType::Text);
        let mut b = model("User", "id", ScalarType::Text);
        b.entities.push(EntityShape {
            name: "_JoinTable".to_owned(),
            fields: vec![],
            unique_sets: vec![],
        });
        let r = compare(&a, &b);
        assert_eq!(r.entity_divergences(), 1);
        assert!(matches!(
            r.divergences[0],
            Divergence::Entity {
                side: Side::OnlyRight,
                ..
            }
        ));
    }
}
