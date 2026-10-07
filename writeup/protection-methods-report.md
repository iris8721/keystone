# Software Protection Methods for a Licensed Payload Delivery Pipeline

An expert review of watermarking, per-download mutation, obfuscation, and sealed delivery, assessed against the current implementation (sealed artifacts, per-fetch HMAC watermark, external protector pass, per-session cache).

## 1. Watermarking and Leak Tracing

The standard taxonomy is Collberg and Nagra's *Surreptitious Software* (Addison-Wesley, 2009; https://dl.acm.org/doi/10.5555/1594894), which divides watermarks into **static** marks (embedded in code or data bytes) and **dynamic** marks (embedded in execution state, e.g., heap topology). A functional taxonomy (Nagra & Thomborson, http://profs.sci.univr.it/%7Egiaco/download/Watermarking-Obfuscation/p177-nagra.pdf) further separates *authorship marks* (prove ownership) from *fingerprinting marks* (identify one copy's recipient) — leak tracing is the fingerprinting case. Every technique trades off **resilience** (survives transformation), **stealth**, **data rate**, and **cost** (Collberg & Thomborson, IEEE TSE 2002, https://www.cs.auckland.ac.nz/~cthombor/Pubs/01027797a.pdf).

The decisive threat model for per-customer fingerprinting is the **collusion attack**: an adversary who buys two copies and byte-diffs them. Boneh and Shaw's *Collusion-Secure Fingerprinting* (https://crypto.stanford.edu/~dabo/pubs/abstracts/finger.html) formalized the "marking assumption": colluders can only detect and alter positions where their copies differ; identical regions are untouchable. A watermark in one contiguous region is maximally exposed — diff two copies, the differing block lights up, overwrite it, and the trace is dead.

**Current design.** The implementation patches the first occurrence of a configured hex pattern with HMAC-SHA256 blocks keyed by a domain-separated watermark secret over the download id (`keystone-server/src/protector.rs::watermark_bytes`), and the download log records the mutated sha plus a watermark flag. Strengths: the tag is keyed (a leaker cannot forge a tag pointing at another customer), deterministic per download id (an operator can re-verify a suspect copy given the log), and pseudorandom (no statistical signature distinguishing it from surrounding bytes). Weakness: it is a single-site, fixed-offset mark — the worst case under the marking assumption. The protector's mutation partially masks naive diffing, but an adversary with two copies can hunt the *pattern-adjacent* region, since the slot sits at a known structural location.

**Countermeasures** (conceptual): multiple insertion sites with per-download randomized offsets, so a colluder cannot tell which differing regions are marks versus mutation; spreading the mark across **instruction selection** (equivalent encodings, register choices, dead-code shape — see the static-mark survey at http://sebastian.doc.gold.ac.uk/papers/BriefSoftwareWatermarking.pdf) so the fingerprint is woven into the mutation itself; and redundancy with error-correcting codes so a partially stripped mark still decodes (the Boneh–Shaw construction exists precisely for this).

## 2. Per-Download Mutation

Byte-unique per-download builds defeat two things at once: hash-based blacklists (a list of sha256s never matches any future copy) and signature-based detection (no stable byte substring survives). This is the server-side polymorphism long used by malware distributors (https://www.sciencedirect.com/science/article/abs/pii/S0950705118302545) and, defensively, the "multicompiler" vision of massive-scale software diversity (Franz, *E unibus pluram*, https://www.nspw.org/papers/2010/nspw2010-franz.pdf).

The standard mutation operators, from the metamorphic-malware literature (https://malwaretech.com/2015/03/code-mutation-polymorphism.html) and code-randomization research (Larsen et al., https://oaklandsok.github.io/papers/larsen2014.pdf): **dead code insertion** (neutral basic blocks; cheap, high byte-delta); **equivalent instruction substitution** (`add x,1` ↔ `sub x,-1`, nop sleds); **basic-block / function reordering**, which breaks offset-based signatures (https://www.seclab.cs.sunysb.edu/seclab/pubs/acsac20.pdf); **register allocation shuffling**, changing large fractions of encoding bits at zero size cost, easiest in a compiler pipeline (https://scholarworks.sjsu.edu/cgi/viewcontent.cgi?article=1305&context=etd_projects); and **random padding**.

The limits are real. **Semantic hashing** collapses shallow mutations back to one class; **binary diffing tools** (BinSim-style trace-based comparison, https://faculty.ist.psu.edu/wu/papers/BinSim.pdf) match binaries across syntactic mutations; and an adversary with two copies and an emulator can **emulation-compare** to separate mutation noise from semantics. Mutation raises the cost of blacklisting and casual signature-matching; it does not resist a motivated analyst. Its honest role here is uniqueness plus watermark camouflage, not reverse-engineering resistance.

## 3. Protectors and Obfuscation

Commercial protectors (VMProtect, Themida-class) stack several independent mechanisms (https://vmpsoft.com/products/vmprotect/, https://www.oreans.com/Themida.php):

- **Code virtualization**: selected functions are compiled to a custom bytecode executed by an embedded interpreter whose architecture is unknown to the attacker; reversing reduces to writing a disassembler for a novel ISA. VMProtect ships multiple VM instances per binary with different register layouts and handler sets (https://vmpsoft.com/vmprotect/user-manual/working-with-vmprotect/).
- **Mutation mode**: instruction-level rewriting (the "Ultra" mode chains mutation then virtualization).
- **Import protection**: hiding/rebuilding the IAT so static analysis sees no API surface ("anti-API scanners", https://themida.com/Themida.php).
- **Anti-debug / anti-VM**: debugger and emulator detection scattered through the protected code, configurable per option (https://www.oreans.com/help/tm/hm_protection-options.htm).
- **Packing and resource encryption**: the on-disk image is a stub plus encrypted sections decrypted at runtime; different keys per protected application.

Pass structure is a cost curve. A light pass (pack + mutate entry code) costs single-digit-percent runtime overhead and mostly defeats static signature scans. Deep virtualization of hot functions can cost 10–100x in the virtualized region, which is why these tools expose per-function granularity and SDK markers (https://vmpsoft.com/vmprotect/user-manual/working-with-vmprotect/page/3/) — virtualize the license check and key handling, mutate the rest, leave hot loops native.

A homegrown protector compares honestly as follows: byte-level mutation, packing, and watermark insertion are achievable in-house with modest effort — the current pipeline already does the mutation-and-reseal half. What is *not* cheap is the hardened VM interpreter with a diversified instruction set; that is the actual moat of VMProtect/Themida-class tools. The pragmatic position is a homegrown mutator for uniqueness plus, where reverse-engineering resistance justifies the runtime cost, a commercial-grade virtualization pass on selected regions — the pipeline (configurable external protector binary) already supports swapping that in.

## 4. Delivery Architecture

The sealed-payload model — a live session receives a signed manifest and wrapped artifact key, downloads an encrypted blob, decrypts in memory — means plaintext never touches disk. Shipping a plain binary instead leaves it copyable, hashable, and redistributable the moment it lands; protection then rests entirely on the obfuscation layer. The sealed model splits defense across transport (TLS), at-rest (AEAD-sealed artifact), and runtime (decrypt-and-load inside the licensed process). The loader's responsibilities — session exchange, keepalive, key unwrap, in-memory decryption, launch — make the license check a *runtime* property, not a download-time one. Download-time checks only gate acquisition; a runtime check binds execution to a live, revocable entitlement, so revocation and lease expiry actually bite. This mirrors how WinLicense fuses licensing into the protection layer rather than bolting a key check onto the installer (https://oreans.com/winlicense.php). The residual exposure is the post-decryption memory image, which is what the protector layer (Section 3) exists to make expensive to dump and reuse.

## 5. Assessment

The current design gets three things right that many commercial pipelines do not: (1) **per-download uniqueness** via mutate-and-reseal, with the manifest attesting the mutated sha and the download log binding sha + watermark flag to an account; (2) a **keyed, deterministic watermark** supporting offline verification of a suspect copy; (3) **no plaintext at rest** on either side — the server re-seals under the same artifact key, and mutated bytes exist only in the bounded per-session cache until popped once. The domain-separated watermark secret (derived from, not equal to, the payload secret) is also correct hygiene.

The highest-value next steps, conceptually:

1. **Multi-site, variable-offset watermarks.** The single fixed-pattern slot is the weakest point under two-copy diffing. Even 4–8 candidate sites with a per-download subset chosen by the watermark secret moves the scheme meaningfully toward the Boneh–Shaw model.
2. **Watermark-in-mutation.** Embed fingerprint bits in the mutation choices themselves (site selection, substitutions, layout permutation) so stripping the mark requires undoing the mutation — the strongest available position, since mutation and fingerprint stop being separable targets.
3. **Mutation strength tiers.** A documented light/medium/heavy pass policy per product, trading protector runtime and binary overhead against threat — the same granularity commercial tools expose per function.
4. **In-the-wild detection.** A planned workflow for scanning recovered copies: recompute candidate tags from the download log, tolerate partial stripping via site redundancy, and record match confidence. A watermark is supporting evidence, not proof of intent — the pipeline's own writeup already frames this correctly.
5. **Collusion modeling.** State the assumed collusion size (2 copies? 10?) explicitly; it determines site count and redundancy, and it is the parameter the current single-site design silently fixes at zero tolerance.

None of these requires architectural change; all are extensions of the existing fetch-time mutation seam.
