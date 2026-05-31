# Citadel Threat Model

**Updated:** 30 May 2026.  
**Status:** Draft.  
**Applies to:** [`specs.md`](specs.md).

This document separates Citadel's threat model from the normative protocol specification. It is intended to support implementation review, security proofs, and later protocol extensions. The base protocol proves cryptographic validity and records sessions. Service authorization remains the responsibility of the SP profile.

## 1. System Boundary

Citadel has three cryptographic phases and one policy phase:

1. **Request and issuance:** a user requests issuance to a license stealth address through a selected request transport, payment flow, or direct handoff; an LP issues an encrypted license containing the LP's full public key, `attr_data`, and a signature, and registers a license leaf. Conforming blockchain-published request and license objects do not contain personal `canonical_attributes`, even encrypted.
2. **License-use proof:** the user proves in zero knowledge that a hidden registered license exists, that the LP signed schema-scoped `attr_data`, and that the user knows the license secret key.
3. **Session recording:** the contract verifies the proof, checks root acceptance, rejects duplicate `session_id`, and stores public session values.
4. **Service authorization:** the SP verifies the cookie opening and applies its own issuer, attribute, challenge, replay, revocation, expiration, and account policy.

The base Citadel protocol covers the request object format, phases 2-3, and the cryptographic part of cookie opening in phase 4. It does not require request storage in the base contract and does not define universal request transport or service authorization.

## 2. Assets

Citadel protects or depends on the following assets:

- user wallet secret keys;
- one-time license secret keys `lsk`;
- LP signing keys;
- SP service keys and service-policy state;
- signed attribute digests and eligibility claims;
- personal `canonical_attributes` held by the user or evaluated by the LP outside blockchain-published data;
- attribute opening material such as `r_attr`;
- encrypted request payloads, request transport metadata, and payment/request binding data;
- encrypted license payloads and license metadata, which should contain `attr_data`, full `pk_lp`, signatures, and non-personal metadata but not personal attributes;
- session cookies and cookie openings;
- Merkle tree state, accepted roots, and Merkle openings;
- contract verifier key and circuit definition;
- deployment metadata, domain constants, generator set, and public-input order;
- privacy of which issued license was used in a session;
- availability of request delivery transports, license registry, session registry, indexers, and SP verification endpoints.

## 3. Adversaries

### 3.1 Passive Chain Observer

Sees all public contract data, including encrypted license blobs, license stealth addresses, license hashes, roots, session public inputs, transaction timing, and fees. If the selected request transport publishes requests, request references, or payment memos on-chain, the observer also sees those payloads and their timing. In a conforming deployment, these blockchain-published objects may contain `attr_data` or commitments to it, but they must not contain personal `canonical_attributes` or attribute openings, whether plaintext or encrypted.

Goals may include linking issuance to session use, identifying the LP or SP behind a session, inferring attributes or challenges, or tracking users across sessions.

### 3.2 Network Observer Or Active Network Attacker

Sees or modifies off-chain communication unless the channel is authenticated and confidential. May attempt request substitution, request correlation, payment/request misbinding, cookie theft, replay, traffic analysis, downgrade attacks, or SP endpoint impersonation.

### 3.3 Malicious User

Controls one or more wallets and may try to:

- forge a license without LP authorization;
- prove membership for an unregistered license;
- use someone else's license;
- create multiple accepted sessions for the same challenge;
- choose arbitrary challenges when the SP expects limited reuse;
- replay cookies;
- manipulate schema interpretation;
- exploit malformed encodings or invalid points;
- use a proof helper to generate proofs while denying policy obligations.

### 3.4 Malicious LP

May sign false attributes, issue outside its policy, publish malformed or duplicate license data, spam the registry, correlate issuance metadata with later disclosures, leak issuance records, place personal data in nonconforming published payloads, or collude with SPs.

A malicious LP cannot be prevented from signing arbitrary claims under its own key. SPs must decide which LP keys they trust and for which schemas.

### 3.5 Malicious SP

May accept weak challenges, accept arbitrary user-chosen `c`, skip issuer or attribute checks, fail to enforce replay or revocation, track users, leak cookies, request excessive disclosures, or collude with LPs.

Users must treat disclosed attributes and cookies as data intentionally revealed to the selected SP profile.

### 3.6 LP/SP Collusion

Combines issuance records, unique attributes learned during issuance, disclosed `attr_data`, disclosed selective attributes, request timing, payment memo metadata, service timing, payments, network metadata, account identifiers, and direct-issuance data to deanonymize users.

Citadel's on-chain zero knowledge does not prevent correlation through data intentionally disclosed to LPs or SPs or through external metadata.

### 3.7 State Or Request-Transport Spammer

Attempts to exhaust license tree capacity, increase indexer load, store bogus license leaves, induce expensive proof verification, or flood LP request transports with empty, duplicate, huge, or malformed requests. If a deployment adds an on-chain request-availability extension or uses payment memos as request transport, the attacker may also try to create persistent request metadata or force LPs to scan noisy payment/request streams.

Gas is an economic deterrent but not a cryptographic defense. Gas-only spam control is a deployment choice and must be justified against persistent storage cost, finite tree capacity, low-fee environments, subsidized attackers, and off-chain scanning costs. Off-chain request transports require their own admission controls, payment thresholds, rate limits, authentication, or abuse handling.

### 3.8 Malicious Or Curious Proof Helper

Receives proving inputs but not `lsk`. May learn metadata such as the license leaf, Merkle path, LP key, `attr_data`, challenge, or intended service, depending on the delegated workflow. A helper for a separate selective-disclosure proof may also learn disclosed or hidden attributes if the user chooses to delegate that proof.

The helper may attempt to reuse `sig_session_auth` for a different session tuple, but the double-key session authorization signature binds the exact public inputs.

### 3.9 Key-Compromise Adversary

Obtains user, LP, SP, transport, or service-channel keys. Consequences depend on the compromised key:

- user wallet key can derive future or stored license secrets depending on wallet design;
- license secret key can open sessions for that license under accepted challenges;
- LP signing key can issue licenses trusted by SPs until revoked by policy;
- request transport, payment service, SP channel, or server keys can expose requests, cookies, or allow service impersonation;
- deployment or verifier-key compromise invalidates protocol assumptions.

### 3.10 Chain Reorganization Or State-Availability Adversary

Exploits stale roots, reorgs, unavailable state, indexer inconsistencies, or unfinalized sessions. Wallets, LPs, and SPs must rely on authenticated and sufficiently finalized contract state.

## 4. Trust Assumptions

Citadel assumes:

- the contract code, verifier key, circuit definition, public-input order, generator set, domain constants, and Merkle parameters match the deployment profile;
- the proof system is sound and zero knowledge for the deployed circuit;
- Poseidon, Schnorr, Pedersen commitments, DHKE, KDF, and AEAD are implemented correctly with valid parameters;
- all external encodings are canonical and validated before cryptographic use;
- wallets and services use fresh CSPRNG randomness or safe deterministic nonce derivation;
- contract state is read from authenticated sources with the deployment's finality policy;
- request transports and payment flows provide the authenticity, confidentiality, finality, and availability claimed by the selected deployment or LP profile;
- wallets and LPs do not publish `canonical_attributes` or attribute openings to blockchain-visible requests, payment memos, events, or contract-stored encrypted license blobs;
- SPs correctly enforce their own policy profiles;
- LPs are trusted only for claims under keys that the SP explicitly accepts;
- users understand that disclosed cookies are bearer credentials unless the SP profile adds binding.

## 5. Security Goals For The Base Protocol

These goals are intended as proof targets or review targets. They are written informally here and can be formalized as games later.

### 5.1 Completeness

An honest user with a valid LP-signed license, a valid Merkle opening under an accepted root, and a policy challenge can generate a proof that the contract accepts. The resulting cookie opens the session values to the intended SP.

### 5.2 License-Use Soundness

Except with negligible probability, any accepted `use_license` proof implies knowledge of witnesses satisfying the circuit relation:

- a hidden `lpk` whose `license_hash` is in the Merkle tree under the accepted `root`;
- a valid LP Schnorr signature on `msg_lic = H(lpk, attr_data)` under hidden `pk_lp.A`;
- a hidden secondary public key `lpk_p` sharing the same discrete-log scalar as `lpk` with respect to `(G, G')`;
- valid openings for `com_0`, `com_1`, and `com_2`;
- a valid session authorization signature over the exact public session tuple.

This goal does not imply that the SP trusts the LP or that the attributes satisfy an SP policy.

### 5.3 Registry Membership Soundness

An adversary should not be able to prove membership for a license public key whose `license_hash` is not included in the tree under an accepted root, assuming collision resistance of the Merkle hash and correctness of the contract root policy.

### 5.4 Issuer-Signature Soundness

An adversary should not be able to make the circuit accept an LP signature for `lpk` and `attr_data` without either knowing a valid signature under some `pk_lp.A` or breaking Schnorr unforgeability.

This does not prevent a malicious LP from signing bad claims under its own key.

### 5.5 License-Secret Possession And Non-Transfer Soundness

An adversary should not be able to prove use of a registered `lpk` unless it can produce a valid double-key authorization for the same hidden scalar behind `lpk` and `lpk_p`.

This proves possession of the license secret at proof time. It does not prevent voluntary sharing of `lsk` outside the protocol.

### 5.6 Nullifier Uniqueness

For a fixed license secret and challenge `c`, `session_id = H(lpk_p, c)` is deterministic. The contract's atomic duplicate check should ensure that at most one session with that `session_id` is accepted.

This goal depends on collision resistance of the session-id hash and correct atomic contract execution. It does not limit the number of sessions a user can create if the SP accepts multiple challenge values.

### 5.7 On-Chain Privacy

A passive chain observer should not learn the hidden license public key, LP key, SP key, personal `canonical_attributes`, challenge, signatures, or Merkle path from the public session record beyond what is leaked by timing, fees, root choice, and external metadata. The public session contains a commitment to `attr_data`, not raw attributes or an encrypted copy of them.

This relies on zero knowledge of the proof system, hiding of commitments, fresh session and commitment randomness, and non-reuse of stealth secrets.

### 5.8 Cookie Opening Soundness

If an SP accepts a base cookie after following the verification algorithm, then the cookie opens the fetched session commitments to the disclosed `pk_sp.A`, `pk_lp.A`, `attr_data`, and `c` values, and those values satisfy the SP's selected policy.

This goal is conditional on the SP actually performing all required policy checks.

### 5.9 Request And License Confidentiality

Encrypted request objects and license payloads should reveal no plaintext to unauthorized parties under the AEAD, KDF, DHKE, and stealth-address assumptions. For personal data, the protocol imposes a stronger publication rule: `canonical_attributes` and attribute openings should not be placed in blockchain-published request or license objects at all, even encrypted. Request metadata leakage is transport-dependent: payment memo timing, payload size, request references, network metadata, direct handoff context, and target LP processing behavior are not hidden by the base protocol. If a user intentionally uses public-address or public-request issuance, the disclosed fields are outside this confidentiality goal.

### 5.10 Deployment Separation

Objects from one deployment should not be valid in another deployment unless the deployments intentionally share all relevant parameters and identifiers. This depends on correct `deployment_id`, domain separation, KDF context, signature transcripts, and metadata checks.

## 6. Explicit Non-Goals And Residual Risks

Citadel does not by itself guarantee:

- SP authorization correctness;
- revocation, unless implemented by a status mechanism or SP profile;
- current validity beyond root acceptance and disclosed/proven expiration rules;
- cookie replay resistance;
- resistance to LP/SP collusion through disclosed `attr_data`, disclosed attributes, issuance records, or metadata;
- resistance to malicious LPs signing false claims;
- resistance to voluntary sharing or sale of `lsk`;
- availability of request delivery transports or license registry capacity;
- privacy against network, payment, payment-memo, browser, account, or device fingerprinting;
- policy safety when the SP accepts arbitrary user-chosen `c`;
- protection after LP signing-key compromise unless the SP updates trust policy;
- privacy if a nonconforming wallet, LP, or deployment publishes personal `canonical_attributes` or attribute openings on-chain, even encrypted.

## 7. Attack Surface And Mitigations

| Area | Attack | Primary mitigation |
| --- | --- | --- |
| Request transport or optional request registry | Empty, duplicate, huge, malformed, misbound, or high-volume request spam | Transport-specific admission policy, memo size limits, request hashes, payment/invoice binding, replay checks, authentication, rate limits, minimum payments, deposits, pruning, or gas/fees only when documented as sufficient |
| License registry | Tree capacity exhaustion or bogus leaves | Issuer allow list, insertion fees, staking, duplicate policy, explicit tree-full behavior |
| Proof verification | Expensive invalid proofs | Charge gas before verification, cap proof size, use efficient verifier, rate-limit at relayers or frontends |
| Roots | Stale or unaccepted roots | Contract root acceptance check, bounded root history, SP freshness rule, finality policy |
| Encodings | Invalid points, identity points, noncanonical scalars | Canonical decoding, subgroup checks, identity rejection, scalar range checks, circuit constraints |
| Signature transcripts | Cross-protocol signature replay | Dedicated signature challenge domains and deployment-bound messages |
| Challenges | Unlimited sessions with arbitrary `c` | SP-defined exact challenge derivation and replay table |
| Cookies | Bearer replay | One-time consumption, SP nonce, account binding, channel binding, client-key binding |
| Attributes | Schema confusion, digest misinterpretation, or accidental publication of personal data | Schema-scoped `attr_data`, explicit `policy_id`, canonical schemas, selective-disclosure proof profiles, and a hard rule that `canonical_attributes` and attribute openings are never put in blockchain-published objects, plaintext or encrypted |
| Revocation | Old roots or hidden status bypass revocation | Expiration in attributes, status accumulator, epoch roots, strict freshness, disclosed/proven revocation state |
| Privacy | LP/SP collusion on disclosed `attr_data`, selective attributes, or metadata | Selective disclosure that keeps `attr_data` hidden from the SP, coarse attributes, timing mitigation, avoid direct issuance when unlinkability matters |
| Proof helpers | Metadata leakage or attempted proof mutation | Do not reveal `lsk`; double-key authorization binds exact public tuple; local proving for sensitive cases |

## 8. Gas, Contract Spam, And Request-Transport Analysis

Gas consumption helps because attackers must pay for transactions, proof verification, and state writes. However, gas does not automatically solve spam for Citadel because:

- the license tree has finite capacity and can be filled by a well-funded or subsidized actor if insertion is permissionless;
- some chains underprice long-term state growth relative to one-time gas;
- gas prices vary over time and may become cheap enough for griefing;
- a deployment may subsidize users or use relayers, weakening the deterrent;
- proof verification gas prices the caller's transaction, but does not protect SPs from off-chain verification attempts or cookie spam.

Removing request storage from the base contract eliminates the base protocol's persistent request-storage spam vector and removes the need for every LP to scan a canonical contract request queue. It does not eliminate request abuse. The selected request transport can still be spammed, especially if it accepts unauthenticated messages, large memos, cheap payment metadata, public request references, or subsidized submissions.

For payment-memo request transport, the LP should define minimum payment thresholds, invoice matching, memo size limits, request hash or reference rules, finality requirements, replay checks, and refund or failure behavior. For off-chain or in-person transport, the LP should define authentication, rate limits, queue limits, retention, and abuse handling.

Gas can be accepted as the deployment's spam-control policy only for the contract resources it actually prices, and only if the deployment explicitly says so and its economics match the expected threat. License insertion, proof verification, optional request availability extensions, payment-memo scanning, and off-chain request intake each need their own admission analysis.

## 9. Proof Obligations For Upcoming Security Work

The following statements are natural proof targets for the next phase.

### 9.1 Circuit Relation Soundness

Formalize the circuit relation and prove that a valid proof implies existence of witnesses satisfying all relation clauses, assuming PlonK soundness and correct circuit implementation.

### 9.2 License-Use Unforgeability

Show that producing an accepted session without a registered LP-signed license implies either breaking Merkle membership soundness, Poseidon collision resistance, Schnorr unforgeability, or proof-system soundness.

### 9.3 Double-Key Authorization Soundness

Show that producing a valid double-key session authorization for `(lpk, lpk_p)` without knowing a common scalar implies solving a discrete-log or related representation problem in `J`, under the transcript model used for Schnorr.

### 9.4 Nullifier Correctness

Show that for any fixed `lsk` and `c`, all accepting proofs produce the same `session_id`, and contract atomicity prevents more than one accepted session with that ID.

### 9.5 On-Chain Zero Knowledge

Show that public session values are simulatable without hidden license identity, LP key, `attr_data`, personal attributes, challenge, signature, or path, assuming proof zero knowledge and hiding commitments.

### 9.6 Cookie Opening Binding

Show that a base cookie accepted by an honest SP binds to the fetched on-chain session and selected `policy_id`, assuming collision resistance and commitment binding.

### 9.7 Deployment Separation

Show that cross-deployment replay requires a collision or a deliberate deployment-parameter reuse, because domain constants, KDFs, signatures, and cookie verification bind `deployment_id` and deployment metadata.

## 10. Review Checklist

Before claiming security for a deployment, reviewers should check:

- exact circuit source matches the published circuit hash;
- verifier key matches the audited circuit and public input order;
- all domain constants are unique and deployment-bound;
- Schnorr transcript domains are separate for LP signatures and session authorization;
- all points are subgroup-checked and identity-rejected where required;
- scalar range checks are correct if `F_c` and `F_s` differ;
- Merkle tree arity, depth, empty leaves, and path order are identical across contract, circuit, and clients;
- request-object encryption, when used, and license encryption use context-bound AEAD associated data;
- contract-stored license payloads include the full canonical `pk_lp` and use `pk_lp.A` consistently for signature verification and LP commitments;
- blockchain-published requests, payment memos, availability payloads, contract events, and contract-stored encrypted license blobs contain no personal `canonical_attributes` or attribute openings, whether plaintext or encrypted;
- request payload, payment memo, request reference, and license blob sizes are bounded by the selected transports;
- license registry insertion policy addresses spam and tree capacity;
- request transports define replay handling, payment binding, finality, retention, and abuse controls;
- SP profiles reject arbitrary challenge values unless unlimited reuse is intended;
- cookie verification includes policy ID, cookie mode, root freshness, issuer trust, and replay rules;
- expiration and revocation are either enforced or explicitly not supported;
- proof-helper workflows never reveal `lsk` and are acceptable under the user's privacy requirements.
