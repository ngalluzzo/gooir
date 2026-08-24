use std::{fs, path::PathBuf};
fn main() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("fixtures/datamodel/prisma");
    for app in [
        "umami-software_umami",
        "lukevella_rallly",
        "ghostfolio_ghostfolio",
        "documenso_documenso",
    ] {
        let src = fs::read_to_string(base.join(format!("{app}.prisma"))).unwrap();
        let w1 = prisma_schema_lifter::lift_prisma_schema(&src).value;
        let low = prisma_schema_lowering::lower_to_prisma(&w1);
        let w2 = prisma_schema_lifter::lift_prisma_schema(&low.value).value;
        let f1: usize = w1.entities.iter().map(|e| e.fields.len()).sum();
        let f2: usize = w2.entities.iter().map(|e| e.fields.len()).sum();
        println!(
            "{app:<30} in={}B out={}B  ent {}->{}  fields {}->{}  rel {}->{}  lossy={}",
            src.len(),
            low.value.len(),
            w1.entities.len(),
            w2.entities.len(),
            f1,
            f2,
            w1.relations.len(),
            w2.relations.len(),
            low.defeats.len()
        );
    }
}
