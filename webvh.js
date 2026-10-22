// Minimal did:webvh 1.0 + Data Integrity (eddsa-jcs-2022) toolkit for browsers and Node.
// ed: an @noble/ed25519 v2 module (uses WebCrypto SHA-512 for the async API).
export function makeKit(ed) {
  const te = new TextEncoder();
  const subtle = globalThis.crypto.subtle;

  // ---------- encoding helpers ----------
  const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  function b58enc(bytes) {
    let n = 0n; for (const b of bytes) n = n * 256n + BigInt(b);
    let s = ""; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
    for (const b of bytes) { if (b === 0) s = "1" + s; else break; }
    return s;
  }
  function b58dec(str) {
    let n = 0n; for (const c of str) { const i = B58.indexOf(c); if (i < 0) throw new Error("bad base58"); n = n * 58n + BigInt(i); }
    const out = []; while (n > 0n) { out.unshift(Number(n % 256n)); n /= 256n; }
    for (const c of str) { if (c === "1") out.unshift(0); else break; }
    return new Uint8Array(out);
  }
  const concat = (...a) => { const o = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
  const sha256 = async (bytes) => new Uint8Array(await subtle.digest("SHA-256", bytes));

  // RFC 8785 JSON Canonicalization (sufficient for the string/int/bool/null/object/array data used here)
  function jcs(v) {
    if (v === null || typeof v !== "object") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
    return "{" + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
  }
  const mhash = async (obj) => b58enc(concat(new Uint8Array([0x12, 0x20]), await sha256(te.encode(jcs(obj)))));
  const multikey = (pub) => "z" + b58enc(concat(new Uint8Array([0xed, 0x01]), pub));
  function pubFromMultikey(mk) {
    if (!mk.startsWith("z")) throw new Error("multikey must be base58btc");
    const b = b58dec(mk.slice(1)); if (b[0] !== 0xed || b[1] !== 0x01) throw new Error("not an Ed25519 multikey");
    return b.slice(2);
  }
  const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const clone = (o) => JSON.parse(JSON.stringify(o));

  // ---------- Data Integrity eddsa-jcs-2022 ----------
  async function diSign(doc, sk, options) {
    const unsecured = clone(doc); delete unsecured.proof;
    const cfg = { type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", created: nowIso(), ...options };
    if (unsecured["@context"] && !cfg["@context"]) cfg["@context"] = unsecured["@context"];
    const msg = concat(await sha256(te.encode(jcs(cfg))), await sha256(te.encode(jcs(unsecured))));
    const sig = await ed.signAsync(msg, sk);
    return { ...cfg, proofValue: "z" + b58enc(sig) };
  }
  async function diVerify(doc, proof, pub) {
    if (proof.type !== "DataIntegrityProof" || proof.cryptosuite !== "eddsa-jcs-2022") throw new Error("unsupported proof");
    const unsecured = clone(doc); delete unsecured.proof;
    const cfg = { ...proof }; const pv = cfg.proofValue; delete cfg.proofValue;
    const msg = concat(await sha256(te.encode(jcs(cfg))), await sha256(te.encode(jcs(unsecured))));
    return ed.verifyAsync(b58dec(pv.slice(1)), msg, pub);
  }

  // ---------- keys ----------
  async function newKey() {
    const sk = ed.utils.randomPrivateKey();
    const pub = await ed.getPublicKeyAsync(sk);
    return { sk, pub, multikey: multikey(pub) };
  }
  async function keyFromSecret(skB58) { const sk = b58dec(skB58); const pub = await ed.getPublicKeyAsync(sk); return { sk, pub, multikey: multikey(pub) }; }

  // ---------- did:webvh creation (version 1) ----------
  // hostPath: "user.github.io/repo/holder" -> did:webvh:{SCID}:user.github.io:repo:holder
  async function createDid(hostPath, key) {
    const parts = hostPath.replace(/^https?:\/\//, "").replace(/\/+$/, "").split("/").map(encodeURIComponent);
    const ident = parts.join(":");
    const ph = "{SCID}";
    const did0 = `did:webvh:${ph}:${ident}`;
    const vm = `${did0}#key-1`;
    const state = {
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
      id: did0,
      verificationMethod: [{ id: vm, type: "Multikey", controller: did0, publicKeyMultibase: key.multikey }],
      authentication: [vm], assertionMethod: [vm],
    };
    const versionTime = nowIso();
    const params = { method: "did:webvh:1.0", scid: ph, updateKeys: [key.multikey] };
    const prelim = { versionId: ph, versionTime, parameters: params, state };
    const scid = await mhash(prelim);
    const entry = JSON.parse(JSON.stringify(prelim).split(ph).join(scid));
    // entry hash: versionId = predecessor (the SCID for version 1)
    entry.versionId = scid;
    const eh = await mhash(entry);
    entry.versionId = "1-" + eh;
    entry.proof = [await diSign(entry, key.sk, {
      verificationMethod: `did:key:${key.multikey}#${key.multikey}`, proofPurpose: "assertionMethod" })];
    const ordered = { versionId: entry.versionId, versionTime: entry.versionTime, parameters: entry.parameters, state: entry.state, proof: entry.proof };
    const didDoc = entry.state;
    const webDoc = JSON.parse(JSON.stringify(didDoc).split(didDoc.id).join(`did:web:${ident}`));
    webDoc.alsoKnownAs = [didDoc.id];
    return { did: didDoc.id, vm: `${didDoc.id}#key-1`, logLine: JSON.stringify(ordered), didDoc, webDoc };
  }

  // ---------- did:webvh resolution (log verification) ----------
  function logUrl(did) {
    const m = did.match(/^did:webvh:([^:]+):(.+)$/); if (!m) throw new Error("not a did:webvh");
    const segs = m[2].split(":").map(decodeURIComponent);
    const host = segs[0].replace("%3A", ":");
    const path = segs.length > 1 ? segs.slice(1).join("/") : ".well-known";
    return `https://${host}/${path}/did.jsonl`;
  }
  async function verifyLog(text, expectDid) {
    const lines = text.split("\n").map(s => s.trim()).filter(Boolean).map(l => JSON.parse(l));
    if (!lines.length) throw new Error("empty log");
    const steps = [];
    let params = {}, prevVid = null, doc = null;
    for (let i = 0; i < lines.length; i++) {
      const e = lines[i];
      const [numStr, hash] = e.versionId.split("-");
      if (Number(numStr) !== i + 1) throw new Error(`v${i + 1}: 버전 번호 불일치`);
      const activeKeys = i === 0 ? e.parameters.updateKeys : params.updateKeys;
      params = { ...params, ...e.parameters };
      if (i === 0) {
        const scid = params.scid;
        const g = clone(e); delete g.proof; g.versionId = "{SCID}";
        const back = JSON.parse(JSON.stringify(g).split(scid).join("{SCID}"));
        if (await mhash(back) !== scid) throw new Error("SCID 유도값 불일치");
        steps.push("SCID 재계산 일치");
        prevVid = scid;
      }
      const h = clone(e); delete h.proof; h.versionId = prevVid;
      if (await mhash(h) !== hash) throw new Error(`v${i + 1}: 항목 해시 불일치(변조/삭제/순서 변경)`);
      let okProof = false;
      for (const p of e.proof || []) {
        const k = p.verificationMethod.split("#")[0].replace("did:key:", "");
        if (!activeKeys.includes(k)) continue;
        const pp = clone(p); // log proofs carry no @context
        if (await diVerify(Object.fromEntries(Object.entries(e).filter(([x]) => x !== "proof")), pp, pubFromMultikey(k))) okProof = true;
      }
      if (!okProof) throw new Error(`v${i + 1}: 승인된 갱신 키의 서명 없음`);
      prevVid = e.versionId; doc = e.state;
    }
    steps.push(`${lines.length}개 항목 해시 체인·서명 검증`);
    if (expectDid && doc.id !== expectDid) throw new Error("DID 불일치");
    return { doc, versionId: prevVid, steps };
  }
  async function resolve(did, fetchFn = fetch) {
    const url = logUrl(did);
    const r = await fetchFn(url, { cache: "no-store" });
    if (!r.ok) throw new Error(`로그를 가져오지 못함 (${r.status}) ${url}`);
    const res = await verifyLog(await r.text(), did);
    return { ...res, url };
  }
  function findVm(doc, vmId, relation) {
    if (!(doc[relation] || []).includes(vmId)) throw new Error(`${vmId} 가 ${relation}에 없음`);
    const vm = (doc.verificationMethod || []).find(m => m.id === vmId);
    if (!vm) throw new Error("검증 키를 찾을 수 없음");
    return pubFromMultikey(vm.publicKeyMultibase);
  }

  return { b58enc, b58dec, jcs, diSign, diVerify, newKey, keyFromSecret, createDid, verifyLog, resolve, logUrl, findVm, nowIso, clone };
}
