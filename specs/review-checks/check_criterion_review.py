"""Structural criterion review gate; does not authenticate actual acceptance."""
import hashlib,json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
PIN="e3091d8569db1aa9bafd02238a46495030783491"
REVIEW_PIN="8410f3ab2d389245f073f9d2d0d17afd3c26d518"
LEDGER="docs/spec-traceability-review-2026-11-20.json"
HASHES=json.loads("{\"specs/001-foundation-and-static-scan/spec.md\":\"b5a31d513c20a509649e69e4eb8c811cc00d64f936df1687d81b9a788ebb4b74\",\"specs/001-foundation-and-static-scan/tasks.md\":\"271cff25cd5c450c07132078aa9ae2d76dbb1d7f814fa0ae458e91a354933b36\",\"specs/002-browser-consent-observation/spec.md\":\"744b35106c25abc1f00f781a4c88b6aaccecb77a307046293788eb41cddb0c61\",\"specs/002-browser-consent-observation/tasks.md\":\"7661cf9df77b8ed27be1e9e350ff5c8b66d666c31898296198d4bdc510c940dd\",\"specs/003-verified-egress-gateway/spec.md\":\"a9c6b2e7b4e88d9fe389d696f3391116f7366bf32929037166767caed399048b\",\"specs/003-verified-egress-gateway/tasks.md\":\"e74eb9fe950eb85d62bc94df7272281e8ce44caea8c121791e93f2b1143a8423\"}")
PACKAGES=["001-foundation-and-static-scan","002-browser-consent-observation","003-verified-egress-gateway"]
def validate(data,baseline,original,current,board,available):
    errors=[]
    for p,h in HASHES.items():
        if hashlib.sha256(original[p]).hexdigest()!=h:errors.append("baseline hash "+p)
        if original[p]!=current[p]:errors.append("unreviewed source change "+p)
    if data.get("schema")!="arvectum.compliance.spec-trace-review/1" or data.get("source_commit")!=PIN or data.get("actual_acceptance_verified") is not False or data.get("public_release_authorized") is not False:errors.append("scope/authority")
    expected={}
    native={}
    for p in PACKAGES:
        text=original["specs/"+p+"/spec.md"].decode()
        reqs=re.findall(r"^- ((?:FR|AT)-[A-Za-z0-9-]+):",text,re.M)
        if len(reqs)!=len(set(reqs)):errors.append("duplicate native requirement "+p)
        expected.update({(p,q):True for q in reqs})
        native[p]=set(re.findall(r"^- \[[ xX]\] ([A-Za-z0-9-]+)\b",original["specs/"+p+"/tasks.md"].decode(),re.M))
    prior={(r["package"],r["requirement_id"]):r for r in baseline["rows"]}
    rows=data["rows"];keys=[(r["package"],r["requirement_id"]) for r in rows]
    if len(keys)!=37 or len(keys)!=len(set(keys)) or set(keys)!=set(expected) or set(keys)!=set(prior):errors.append("criterion coverage")
    checks=re.findall(r"^- \[([ xX])\] (REVIEW-[A-Z0-9-]+) —",board,re.M)
    mapping={k:v.lower()=="x" for v,k in checks}
    if len(checks)!=37 or len(mapping)!=37:errors.append("review task coverage")
    for r in rows:
        k=(r["package"],r["requirement_id"]);old=prior.get(k)
        if not old:continue
        ident="REVIEW-"+k[0][:3]+"-"+k[1]
        if any(r.get(f)!=old.get(f) for f in ("task_ids","test_candidates","review_needed")):errors.append("unreviewed native linkage drift "+ident)
        if not r["task_ids"] or not set(r["task_ids"])<=native[k[0]]:errors.append("native task reference "+ident)
        if not r["test_candidates"] or not set(r["test_candidates"])<=available:errors.append("test path reference "+ident)
        state=r.get("state")
        if state not in {"candidate_unverified","verified"} or r.get("review_task_id")!=ident or ident not in mapping or mapping[ident]!=(state=="verified"):errors.append("review state "+ident)
        if state=="verified":
            ev=r.get("acceptance_evidence",[])
            if not ev or any(e.get("criterion")!=k[1] or e.get("package")!=k[0] or e.get("outcome")!="pass" or not re.fullmatch(r"[a-f0-9]{64}",e.get("artifact_sha256","")) or not e.get("receipt_ref") or not e.get("review_ref") for e in ev):errors.append("missing criterion-specific reviewed evidence "+ident)
    return errors
def inputs():
    def read(ref,p):return subprocess.check_output(["git","-C",str(ROOT),"show",ref+":"+p])
    original={p:read(PIN,p) for p in HASHES}; current={p:(ROOT/p).read_bytes() for p in HASHES}
    data=json.loads((ROOT/LEDGER).read_text());baseline=json.loads(read(REVIEW_PIN,LEDGER))
    available=set(subprocess.check_output(["git","-C",str(ROOT),"ls-tree","-r","--name-only","HEAD"],text=True).splitlines())
    return data,baseline,original,current,(ROOT/"docs/spec-criterion-review-tasks-2026-11-20.md").read_text(),available
if __name__=="__main__":
    errors=validate(*inputs())
    if errors:raise SystemExit("\n".join(errors))
    print("Structural PASS: 37 native criteria and review tasks; public release and actual acceptance not established.")
