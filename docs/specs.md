# Citadel Protocol Specification

**Updated:** 30 May 2026.  
**Status:** Draft.  

Citadel lets a user obtain an encrypted license from a License Provider (LP), prove on-chain that a registered license exists without revealing which license it is, and then disclose a session cookie to a Service Provider (SP). The protocol deliberately separates cryptographic validity from service authorization. The contract verifies the zero-knowledge proof and records a session. The SP decides whether that session satisfies its own service policy.

This document is normative for the base Citadel protocol shape. SP choices such as accepted issuers, attribute predicates, challenge format, replay handling, revocation, expiration, account binding, and rate limits are policy-profile inputs, not universal protocol constants.

The words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in uppercase.

## 1. Scope And Design Boundary

Citadel provides the following base guarantees:

- A user can prove possession of the license secret key corresponding to a hidden license public key.
- A user can prove that the hidden license public key is registered in the contract's license tree under an accepted Merkle root.
- An LP signature binds schema-scoped `attr_data` to the hidden license public key. For schemas that contain personal or user-specific data, `attr_data` is a digest of `canonical_attributes`, not the personal data itself.
- Public session data does not reveal the user wallet key, license public key, LP key, SP key, attributes, challenge, LP signature, session authorization signature, or Merkle path.
- For a fixed hidden license and a fixed SP-accepted challenge value, the contract accepts at most one session.
- An SP can verify that a disclosed cookie opens the public on-chain session values and then apply its own policy.

Citadel does **not** grant service access by itself. The SP MUST still check issuer trust, attribute semantics, challenge acceptance, root freshness, revocation, expiration, replay rules, account binding, channel binding, and rate limits required by its own policy profile.

Citadel also does not automatically provide:

- replay protection for a disclosed cookie;
- revocation or current-validity checks beyond membership in an accepted root;
- issuer-verifier unlinkability when attributes are unique, when timing or network metadata is identifying, or when the LP and SP collude;
- availability protection for request delivery, registry storage, or SP service endpoints;
- authorization for every service that accepts Citadel proofs.

The standalone [threat model](security.md) defines adversaries, assets, security goals, residual risks, and proof obligations. The protocol specification keeps only the normative mechanics needed for interoperable implementations.

## 2. Parties, Identifiers, And Secrets

### 2.1 Parties

- **User:** controls a wallet key pair, requests licenses, owns license secret keys, opens sessions, and sends cookies to SPs.
- **License Provider (LP):** evaluates requests, defines signed attributes, signs licenses, and publishes encrypted licenses.
- **Service Provider (SP):** publishes a policy profile, verifies cookies, and grants or denies service.
- **Contract:** stores encrypted license blobs, stores issued license commitments, maintains accepted Merkle roots, verifies license-use proofs, rejects duplicate session IDs, and stores public session records. The base contract does not store issuance requests unless a deployment adds an explicit request-availability extension.
- **Validators:** execute the contract and verify proofs according to the deployed verifier key.
- **Optional proof helper:** may help generate a proof, but MUST NOT receive the user's license secret key.

The LP and SP MAY be the same legal or operational entity, but the protocol treats them as separate roles. If they are the same entity, privacy against issuer-verifier correlation is weaker and depends heavily on the selected attribute-disclosure profile.

### 2.2 Field And Group Notation

Citadel uses a proof-system field and a prime-order subgroup of Jubjub. Implementations MUST be explicit about field boundaries.

- `F_c`: the field used by the circuit and Poseidon arithmetic.
- `F_s`: the scalar field used for Jubjub subgroup scalar multiplication.
- `J`: the prime-order Jubjub subgroup used for Phoenix-style keys, stealth addresses, Schnorr signatures, and Pedersen commitments.
- `G` and `G'`: independent fixed generators of `J`.

If an implementation uses the same concrete field representation for `F_c` and `F_s`, it MAY expose a single scalar type. If `F_c` and `F_s` differ, the deployment profile MUST define canonical encodings and range checks for every scalar represented in the circuit. Values used as Pedersen coefficients, Schnorr scalars, secret keys, stealth scalars, and blinding factors are elements of `F_s`; values used as public inputs and Poseidon state elements are elements of `F_c`.

The discrete logarithm of `G'` with respect to `G` MUST be unknown. The generator set MUST be fixed by the deployment and included in the audited circuit definition.

### 2.3 Core Identifiers

The following names are used throughout the specification:

- `pk = (A, B)`: Phoenix-style public key.
- `pk_user`, `pk_lp`, `pk_sp`: role-specific Phoenix public keys for the user, LP, and SP.
- `sk = (a, b)`: matching Phoenix-style secret key.
- `lsa`: license stealth address.
- `rsa`: request stealth address.
- `lsk`: one-time license secret key derived by the user for `lsa`.
- `lpk = lsk * G`: one-time license public key, equal to the public key carried by `lsa`.
- `lpk_p = lsk * G'`: secondary license public key used only for nullification and double-key authorization.
- `pk_lp.A`: LP signing point used to verify the license signature.
- `pk_sp.A`: SP service point to which a cookie is bound.
- `schema_id`: versioned identifier for the signed attribute schema.
- `policy_id`: versioned identifier for an SP authorization profile.
- `canonical_attributes`: schema-defined attribute values about the user or license holder, including any personal data, eligibility facts, validity fields, or revocation handles that a schema treats as attributes. `canonical_attributes` MUST NOT be written to blockchain-published data, contract state, contract events, payment memos, request-availability payloads, or contract-stored encrypted license blobs, whether plaintext or encrypted.
- `attr_opening`: local or off-chain material needed to recompute `attr_data` from `canonical_attributes`, such as `r_attr` and any schema-defined salts or normalization metadata. `attr_opening` is not a base on-chain object.
- `attr_data`: schema-scoped scalar digest or non-personal scalar value representing the LP-signed attributes. For schemas that contain personal or user-specific data, it MUST be computed from `canonical_attributes` through the digest construction in Section 11. It is the only attribute-derived value that may appear in blockchain-published protocol objects, and the public session stores only a commitment to it.
- `c`: SP policy challenge value. It controls nullification and reuse.
- `root`: accepted Merkle root of the license registry.
- `session_id`: public nullifier derived from `lpk_p` and `c`.
- `session_hash`: public commitment tying a session cookie to `pk_sp.A` and fresh session randomness.
- `com_0`: commitment to `pk_lp.A`.
- `com_1`: Pedersen commitment to `attr_data`.
- `com_2`: Pedersen commitment to `c`.

The circuit receives `lpk` and `lpk_p` as private witness points. It does not receive `lsk` and does not compute either point from `lsk`. Instead, it verifies a double-key Schnorr authorization proving knowledge of the same hidden scalar for both points.

## 3. Deployment Profile And Domain Separation

### 3.1 Deployment Profile

Each Citadel deployment MUST define:

- protocol version;
- chain ID;
- contract ID;
- compact deployment ID;
- proof system and verifier key;
- circuit hash and public-input order;
- generator set;
- Poseidon parameters and domain constants;
- compact hash-context derivation;
- Merkle tree parameters;
- root acceptance policy;
- request transport, admission, replay, duplicate, size-limit, retention, payment-binding, and spam-control policy, if request objects are used;
- license issuance access policy;
- duplicate `license_hash` policy;
- tree-full behavior;
- supported attribute schemas;
- supported SP policy profiles, if any are published by the deployment;
- finality or reorganization policy for wallets, LPs, and SPs;
- upgrade and deprecation rules for protocol, circuit, domain, generator, and parameter changes.

The contract MUST expose enough metadata for wallets and SPs to verify that they are using the intended verifier key, tree parameters, domain context, root policy, and protocol version. New clients SHOULD prefer named metadata fields over positional tuple returns.

### 3.2 Compact Deployment Context

For circuit efficiency, deployment metadata is represented inside protocol objects by one field element, `deployment_id`. The deployment profile defines how this identifier is assigned or derived from the protocol version, chain ID, contract ID, verifier key, circuit hash, generator set, domain constants, and Merkle parameters.

Domain separation metadata is compressed into one field element per logical hash domain:

`ctx_D = PoseidonOther(CITADEL_CONTEXT_V1, deployment_id, domain_id_D)`

where `domain_id_D` is the fixed identifier for domain `D`. Circuit hash preimages MUST use `ctx_D` as their first element instead of absorbing the uncompressed version, chain, contract, and domain values separately.

The uncompressed deployment metadata remains part of the deployment profile. The compact `deployment_id` is the value carried by requests, licenses, session cookies, and circuit context.

Any change to public-input order, hash preimages, signature transcripts, KDF inputs, domain constants, generator set, Merkle parameters, circuit constraints, proof-system parameters, or verifier key defines a new protocol or circuit version. Implementations MUST NOT silently mix data from different versions.

### 3.3 Domain-Separated Hashes

Poseidon is used for values that must be reproduced inside the circuit. Every Poseidon use MUST be domain-separated.

This specification writes a domain-separated hash as:

`H[DOMAIN](x_0, ..., x_n)`

For domains used inside the base circuit, this means:

`H(ctx_DOMAIN, x_0, ..., x_n)`

Merkle internal nodes are the exception: they use the fixed Poseidon `MERKLE4` domain for exactly four children.

When a scalar output is required from points, field elements, or byte strings, canonical encodings are mapped into field elements before hashing:

`H_SCALAR[DOMAIN](...)`

Required base domains:

- `CITADEL_CONTEXT_V1`
- `CITADEL_STEALTH_DERIVE_V1`
- `CITADEL_REQUEST_KEY_V1`
- `CITADEL_LICENSE_KEY_V1`
- `CITADEL_LICENSE_HASH_V1`
- `CITADEL_LICENSE_SIG_MSG_V1`
- `CITADEL_LICENSE_SIG_CHALLENGE_V1`
- `CITADEL_SESSION_HASH_V1`
- `CITADEL_SESSION_AUTH_V1`
- `CITADEL_SESSION_SIG_CHALLENGE_V1`
- `CITADEL_SESSION_ID_V1`
- `CITADEL_LP_COMMITMENT_V1`
- `CITADEL_ATTR_DATA_V1`
- `CITADEL_REQUEST_ID_V1`
- `CITADEL_POLICY_ID_V1`
- `CITADEL_POLICY_CHALLENGE_V1`

A deployment MAY define additional domains for new circuits, transports, or SP policy profiles. It MUST NOT reuse the same domain for different semantic objects.

## 4. Canonical Encoding And Validation

Every externally supplied value MUST be validated before cryptographic use.

For Jubjub points, implementations MUST:

- require canonical byte encoding;
- reject decoding failures;
- check that the point is on the curve;
- check that the point is in the prime-order subgroup;
- reject the identity point unless a specific protocol field explicitly allows it;
- compare trust-list entries using canonical encodings;
- define a single canonical coordinate order for hash preimages and public input serialization.

For scalar field elements, implementations MUST:

- require canonical scalar or field encoding;
- reject out-of-range values;
- reject ambiguous byte encodings;
- define deterministic byte-to-field and hash-to-field mappings;
- range-check `F_s` scalars represented inside an `F_c` circuit when the two fields differ.

For structured data, implementations MUST:

- use versioned canonical serialization;
- avoid ad hoc concatenation without lengths or type tags;
- bind the `deployment_id`, schema ID, policy ID, and cookie mode where relevant;
- enforce maximum payload sizes for request payloads and contract-stored license blobs;
- reject unknown critical fields unless the object version explicitly permits forward-compatible extension.

The same validation rules apply to requests, licenses, public inputs, cookies, LP keys, SP keys, Merkle openings, signatures, and off-chain predicate proof inputs.

The circuit MUST constrain private witness points used as group elements, including `lpk`, `lpk_p`, and `pk_lp.A`, to be valid non-identity points in the intended subgroup or use complete audited group gadgets that enforce the equivalent relation. Off-chain verifiers MUST validate all disclosed points independently.

## 5. Cryptographic Building Blocks

### 5.1 Phoenix-Style Keys

Each party uses:

- Secret key: `sk = (a, b)` where `a, b in F_s`.
- Public key: `pk = (A, B)` where `A = aG` and `B = bG`.

The `A` component is used for DHKE and signing where specified. The `B` component is used in stealth-address derivation. Secret scalars SHOULD be sampled uniformly from nonzero elements of `F_s`. Public keys MUST be canonical Jubjub points and MUST pass the validation rules in Section 4.

Role-specific keys are written as `sk_user`, `pk_user`, `sk_lp`, `pk_lp`, `sk_sp`, and `pk_sp`. Public-key names refer to full Phoenix public keys unless a formula names a component explicitly, for example `pk_lp.A`, `pk_sp.A`, or `pk_user.A`.

SP profiles MUST state whether an issuer or service is identified by a full Phoenix public key, by its `A` component, or by another deployment identifier. All comparisons MUST use canonical encodings.

### 5.2 Stealth Addresses

A Citadel stealth address contains a one-time public key and a sender public nonce:

`sa = (opk, R)`

where:

- `r <- F_s` is fresh sender randomness;
- `R = rG`;
- `K = r * pk_recipient.A`;
- `opk = H_SCALAR[CITADEL_STEALTH_DERIVE_V1](K) * G + pk_recipient.B`.

The recipient detects ownership by computing `K = sk_recipient.a * R` and checking:

`opk = H_SCALAR[CITADEL_STEALTH_DERIVE_V1](K) * G + pk_recipient.B`

The recipient's one-time secret key is:

`nsk = H_SCALAR[CITADEL_STEALTH_DERIVE_V1](K) + sk_recipient.b`

For a license stealth address `lsa`, Citadel names the one-time public key `lpk`. For a request stealth address `rsa`, Citadel names it `rpk`.

Fresh `r` MUST be used for every stealth address. Reusing stealth randomness or one-time secrets can link objects and can break privacy. If the derived one-time secret or one-time public key is invalid under the deployment's key rules, the sender MUST resample.

### 5.3 Schnorr Signatures

Citadel uses Jubjub Schnorr signatures in two roles:

- single-key Schnorr for LP license signatures;
- double-key Schnorr for proving license-secret possession while binding both `lpk` and `lpk_p`.

Schnorr signing nonces MUST be generated with a CSPRNG or by deterministic nonce derivation that is domain-separated and binds the signing secret, public key, message, and protocol context. A signing nonce MUST NOT be reused with the same signing key.

#### 5.3.1 LP License Signature

For LP signing key `a`, public key `A = aG`, and message `m`, a license signature is:

1. sample or derive nonce `n <- F_s`;
2. compute `R = nG`;
3. compute `e = H_SCALAR[CITADEL_LICENSE_SIG_CHALLENGE_V1](A, R, m)`;
4. compute `z = n + e * a`;
5. output `sig = (R, z)`.

Verification checks:

`zG == R + eA`

The signed license message is:

`msg_lic = H[CITADEL_LICENSE_SIG_MSG_V1](lpk.u, lpk.v, attr_data)`

`attr_data` MUST already be schema-scoped. Raw personal or user-specific attributes MUST NOT be signed directly or placed in the license signature message; they MUST first be reduced to the attribute digest construction in Section 11. A directly encoded scalar is permitted only for a schema-defined non-personal value whose semantics are unambiguous under the schema and SP profile.

#### 5.3.2 Double-Key Session Authorization Signature

For license secret `x = lsk`, public keys `P = xG = lpk` and `P' = xG' = lpk_p`, and message `m`, a double-key signature is:

1. sample or derive nonce `n <- F_s`;
2. compute `R = nG` and `R' = nG'`;
3. compute `e = H_SCALAR[CITADEL_SESSION_SIG_CHALLENGE_V1](P, P', R, R', m)`;
4. compute `z = n + e * x`;
5. output `sig = (R, R', z)`.

Verification checks both equations:

`zG  == R  + eP`

`zG' == R' + eP'`

The double-key statement proves knowledge of the same scalar for `G` and `G'`. The transcript MUST bind both public keys, both nonce points, the message, and the deployment-specific signature domain.

### 5.4 Commitments

Citadel uses:

- a Poseidon hash commitment for the LP public signing point:

  `com_0 = H[CITADEL_LP_COMMITMENT_V1](pk_lp.A.u, pk_lp.A.v, s_0)`

- Pedersen commitments for scalar values:

  `com_1 = attr_data * G + s_1 * G'`

  `com_2 = c * G + s_2 * G'`

`s_0`, `s_1`, and `s_2` MUST be fresh random scalar values for every session. `attr_data` and `c` MUST be canonical scalar values. If natural attribute data is not a non-personal schema-scoped scalar, and for every schema containing personal or user-specific data, it MUST first be converted into a canonical field digest as described in Section 11. Raw `canonical_attributes` never enter `com_1`, the base circuit, or contract state.

`com_1` and `com_2` MUST be serialized as canonical Jubjub points. Verifiers MUST reject malformed commitment points and MUST reject identity commitments unless the deployment explicitly allows them for a specific field.

### 5.5 Encryption And KDF

Encrypted request objects and license payloads MUST use authenticated encryption. The concrete AEAD MAY be supplied by the deployment, but it MUST provide confidentiality, integrity, explicit failure on tampering, unambiguous serialization, and nonce-misuse resistance appropriate to the chosen mode.

Every encryption key MUST be derived with a domain-separated KDF that includes:

- `deployment_id`;
- message type;
- sender-visible and recipient-visible public context;
- the DH shared point or other approved secret input;
- a salt or nonce value.

The AEAD associated data MUST include all visible fields that identify the payload context, including at least `deployment_id`, object version, message type, visible stealth address, and any declared schema or policy identifier.

AEAD nonces or salts MUST be unique for a given encryption key unless the chosen AEAD is explicitly nonce-misuse-resistant. Even with a nonce-misuse-resistant AEAD, implementations SHOULD still keep nonces unique.

Decryption failure MUST be treated as authentication failure. Callers MUST NOT use unauthenticated plaintext.

License encryption key material sent inside a request MUST NOT be the license secret key and MUST NOT allow recovery of the license secret key. It MAY be derived deterministically from `lsk` through a one-way KDF with a license-encryption domain, or it MAY be generated independently and stored by the user. The LP may learn the license encryption key material, but must not learn `lsk`. In direct issuance without a request object, the deployment MUST define an equivalent license-encryption key derivation, typically from the DH shared secret used to create the license stealth address.

### 5.6 Merkle Tree

The license registry is a fixed-parameter Merkle tree over license leaves.

Deployment parameters:

- `MERKLE_ARITY`: tree arity. For this circuit version it MUST be `4`.
- `MERKLE_DEPTH`: tree depth.
- `EMPTY_LEAF`: empty leaf value.
- `ROOT_HISTORY_SIZE`: number of previous roots accepted by the contract, if any.

The contract, circuit, wallets, LPs, and SPs MUST use the same tree parameters. The contract MUST reject license-use proofs whose public `root` is not accepted under the deployment's root policy.

Accepted roots MUST come from authenticated contract state, not from user-provided claims.

The license leaf value is:

`license_hash = H[CITADEL_LICENSE_HASH_V1](lpk.u, lpk.v)`

Internal nodes are computed with the fixed Poseidon 4-ary Merkle domain:

`parent = Poseidon[MERKLE4](child_0, child_1, child_2, child_3)`

Child order is part of the Merkle opening. Empty child slots use the deployment `EMPTY_LEAF` and empty-subtree values.

The recommended root policy is:

- accept the current root;
- optionally accept a bounded history of previous roots to tolerate proving and transaction latency.

An SP MAY impose a stricter freshness rule than the contract, for example requiring the root to be no older than `N` blocks or produced after a policy-specific epoch boundary.

### 5.7 Proof System

The base circuit is verified by the deployed PlonK verifier key. The verifier key, circuit hash, public input order, proof-system parameters, and any setup assumptions MUST be part of the deployment profile and MUST be available to wallets and SPs through authenticated deployment metadata.

## 6. Data Objects

### 6.1 Issuance Request

An issuance request is a transport-neutral object asking an LP to issue a license to a user-controlled license destination. It is not part of the base contract state and is not consumed by the license-use circuit. A deployment MAY use this object for private request-based issuance, or it MAY use direct issuance without an encrypted request when the relevant privacy tradeoffs are acceptable.

Fields for the encrypted request object:

- `version`
- `deployment_id`
- `rsa`: request stealth address addressed to the LP
- `enc`: AEAD encryption of `lsa || k_lic_enc || request_context`

Where:

- `lsa` is the license stealth address where the license will be issued.
- `k_lic_enc` is license encryption key material known to the user and disclosed to the LP only inside the encrypted request.
- `request_context` includes `deployment_id`, intended LP key or LP identifier, object version, requested schema or policy information, any LP-required application metadata, and any transport binding required by the deployment profile. Transport binding MAY include an invoice ID, payment reference, transaction hash commitment, expected payment recipient, payment asset, payment amount, request expiry, or off-chain authorization data.

If the request object, request reference, payment memo, or availability payload is stored on-chain or otherwise published as persistent online protocol data, it MUST NOT contain `canonical_attributes`, disclosed attribute values, or `attr_opening`, even inside encrypted fields. An LP that needs personal data to evaluate eligibility MUST collect or verify it through an off-chain process that is not republished as a contract-stored request or license object. The only attribute-derived value allowed in such blockchain-visible request material is a schema-scoped digest or commitment, such as `attr_data` or a hash binding supplied by the selected request profile.

The request ID is:

`request_id = H[CITADEL_REQUEST_ID_V1](version, deployment_id, rsa, enc)`

LPs MUST maintain a replay policy for request IDs and license stealth addresses. They MUST NOT issue duplicate licenses for the same `lsa` unless duplicate issuance is an explicit application requirement.

After decryption, the LP MUST check that `request_context` matches the visible request fields, intended LP key, `deployment_id`, deployment profile, and selected request transport. A mismatch invalidates the request.

Request delivery is selected by the deployment or application profile. Acceptable transports include an authenticated off-chain channel, an in-person handoff such as a QR code, a payment transaction memo or equivalent transaction metadata field, or an optional authenticated availability layer. The base Citadel contract MUST NOT be assumed to store or make requests available. If a deployment adds a contract-backed request registry, it is an extension and MUST specify insertion authorization, retention, retrieval, payload size limits, duplicate handling, fees, and spam policy.

If a request is carried in payment transaction metadata, the request payload MUST be encrypted unless public-address or public-request disclosure is an explicit application choice. This exception permits disclosure of non-personal request-routing fields only; it does not permit `canonical_attributes`, disclosed attribute values, or `attr_opening` to be placed in blockchain-visible metadata. The LP MUST verify payment finality, payment recipient, asset, amount, memo or payload size limits, and the binding between the payment or invoice and `request_id` or `lsa` before issuance. If the transaction metadata cannot fit the complete request, it MAY carry a request reference plus a cryptographic hash of the referenced request object. The referenced payload MUST be fetched from an authenticated source or verified against the hash before use.

If privacy is not required, the user MAY provide `lsa` and license encryption material through an authenticated channel, or MAY provide a static public address or direct-issuance target as specified in Section 8.4. Public-address issuance is a lower-privacy mode because the LP can associate the issued license with the disclosed address, account, payment, or in-person identity.

### 6.2 License

A license is an encrypted asset published by an LP.

Fields:

- `version`
- `deployment_id`
- `lsa` or visible `lpk` coordinates: license stealth address or visible license public key coordinates needed to compute the registry leaf
- `enc`: AEAD encryption of `sig_lic || attr_data || pk_lp || license_context`

Where:

- `lpk = lsa.lpk` is the license public key.
- `attr_data` is the schema-scoped value signed by the LP. For schemas that contain personal or user-specific data, it MUST be a digest of `canonical_attributes` as defined in Section 11.
- `pk_lp` is the full Phoenix public key of the License Provider, encoded in the same canonical public-key or address format used by wallets and SP issuer-trust profiles. Its `A` component is the signing point used for `sig_lic` and the point committed by `com_0` in later sessions.
- `license_context` contains schema ID, issuance metadata, expiration or no-expiration marker when that marker is not personal data, and deployment context needed by wallets to verify and interpret the license. User-specific validity or revocation fields that are personal data MUST be represented through `canonical_attributes` and `attr_data`, then disclosed or proven according to the selected SP profile.
- `sig_lic` is the LP signature over:

  `msg_lic = H[CITADEL_LICENSE_SIG_MSG_V1](lpk.u, lpk.v, attr_data)`

A contract-stored license payload MUST NOT contain `canonical_attributes`, disclosed attribute values, or `attr_opening`, whether plaintext or encrypted. The license payload gives the wallet the signed digest, LP full public key, and non-personal interpretation metadata; it does not provide an encrypted online backup of the user's personal data.

The registry leaf is:

`license_hash = H[CITADEL_LICENSE_HASH_V1](lpk.u, lpk.v)`

The contract MUST derive or verify `license_hash` from visible license public data, either from `lsa` when the license object is supplied to the contract or from explicit visible `lpk` coordinates in the issuance argument. It MUST NOT accept a caller-supplied hash that is inconsistent with the visible license public key.

Issued license stealth addresses are public registry data. The privacy property is that a later session proof does not reveal which public license was used.

### 6.3 Session

A session is the public on-chain record created after a successful license-use proof.

The public input order is fixed:

1. `session_id`
2. `session_hash`
3. `com_0`
4. `com_1.x`
5. `com_1.y`
6. `com_2.x`
7. `com_2.y`
8. `root`

The contract stores the whole public input vector and keys the session by `session_id`. All implementations MUST preserve this order for this circuit version.

The public input vector does not carry `deployment_id` as a public input. It is a deployment constant used to derive the compact context scalars for the circuit's domain-separated hashes. A session record MUST be interpreted only together with the deployment metadata under which its proof was verified.

### 6.4 Base Session Cookie

The base disclosure cookie sent by the user to the SP is a versioned envelope containing:

- `version`
- `deployment_id`
- `cookie_mode = base`
- `policy_id`
- `session_id`
- `pk_sp` or the SP identifier that resolves unambiguously to `pk_sp.A` under the policy
- `r_session`
- `pk_lp` or the issuer identifier required by the policy
- `attr_data`
- optional off-chain attribute opening data, such as disclosed attributes and `r_attr`, when `attr_data` is a digest and the base profile requires semantic verification without a separate proof
- `c`
- `s_0`
- `s_1`
- `s_2`
- optional profile-defined account, channel, client-key, nonce, or request-binding data

Here `pk_sp` and `pk_lp` are full Phoenix public keys unless the selected profile identifies services or issuers by another canonical identifier. The base protocol binds the session to `pk_sp.A` and commits to `pk_lp.A`.

The base cookie reveals the openings needed by the SP. In the base mode, `attr_data` is disclosed to the SP. If `attr_data` is a digest, the SP cannot check the underlying attribute semantics unless the user also discloses a valid opening over the off-chain service channel or provides a selective-disclosure proof. Cookies and attribute openings are off-chain service credentials; wallets and SPs MUST NOT submit them to the blockchain or publish them as persistent online protocol data.

The base session cookie is a bearer credential unless the selected SP profile adds binding. Anyone who obtains it can attempt to replay it to the SP. SPs MUST treat cookies as sensitive credentials and MUST define a replay policy before using Citadel for real service access.

The cookie or the surrounding authenticated request MUST identify the SP policy profile being used. The SP MUST NOT infer a policy profile from fields that could be valid under multiple profiles.

### 6.5 Selective-Disclosure Cookie

In selective-disclosure mode, the user does not reveal the `com_1` opening directly. The cookie contains the same envelope fields as the base cookie, but `attr_data` and `s_1` MAY be omitted or replaced by disclosed attributes and an off-chain predicate proof, depending on the SP profile. The proof uses `canonical_attributes` and `attr_opening` supplied by the user from local knowledge or a non-chain issuance workflow; they are not recovered from the contract-stored license payload.

The SP profile MUST define the public inputs and statement of the selective-disclosure proof.

Selective-disclosure cookies and proofs MUST be bound to `session_id`, `deployment_id`, `policy_id`, cookie mode, and the SP challenge or nonce when the profile uses one.

## 7. Contract State, Registry Policy, And Interfaces

### 7.1 Request Transport

The base contract has no request registry. Request delivery is an application or deployment transport, not a cryptographic requirement of the license-use circuit. Each deployment or LP profile that supports request-based issuance MUST define accepted request transports, whether requests are encrypted or intentionally public, maximum payload or memo sizes, replay and duplicate policy, payment or invoice binding, finality requirements, retention and discovery expectations, and admission or spam control.

Successful request delivery, memo inclusion, or payment submission does not mean an LP has accepted, decrypted, or even seen the request. LPs MUST still enforce their own `request_id`, `lsa`, eligibility, payment, replay, issuance, and business policies after decryption or direct handoff.

A deployment MAY add a contract-backed request availability extension. Such an extension is outside the base contract interface and MUST specify its own insertion authorization, retrieval API, retention policy, size limits, duplicate handling, fees, and spam controls. Gas is an economic deterrent, not a cryptographic invariant; it is sufficient only if the deployment explicitly accepts the economics and operational cost assumptions.

### 7.2 License Registry

The license registry has finite capacity. Each deployment MUST define who may insert license leaves and how storage spam is controlled.

Acceptable issuance policies include:

- allow-listed LP callers;
- permissionless insertion with fees high enough to price storage, tree capacity, and proof costs;
- staking or rate-limited issuer registration;
- application-specific governance;
- deployment-specific admission control.

The contract MUST define behavior when the tree is full. It MUST NOT silently overwrite existing leaves. A deployment MAY rotate to a new tree or contract, but the migration and accepted-root policy MUST be explicit.

The contract or deployment profile MUST define duplicate `license_hash` handling. Duplicate leaves SHOULD be rejected unless renewal, migration, or another application rule explicitly requires them. If duplicates are allowed, they do not create independent nullification capacity because `session_id` depends on the hidden license key and challenge, not on the leaf position.

SP trust in LPs is separate from contract insertion permission. A license leaf being present in the registry proves registration, not that every SP trusts the issuer.

### 7.3 Base Contract Interface

The base contract interface for wallets, LPs, SPs, and web clients SHOULD expose at least:

- `issue_license`: store an encrypted license blob and register its license leaf.
- `get_licenses`: stream stored licenses by block-height range or indexed range.
- `get_license`: fetch a license by license tree position.
- `get_merkle_opening`: fetch the Merkle opening for a license tree position.
- `use_license`: verify a license-use proof and store the resulting session.
- `get_session`: fetch a session by `session_id`.
- `get_metadata`: fetch deployment metadata.
- `get_current_root` and `get_accepted_roots`: inspect root state.
- `get_state_info`: fetch named license, tree, session, and root counters.

A request-availability extension MAY expose `insert_request`, `get_requests`, or `get_request`, but those calls are not part of the base Citadel contract interface.

Legacy or constrained clients MAY expose smaller compatibility queries, such as tuple-shaped `get_info`, but new clients SHOULD prefer named return types to avoid positional ambiguity.

## 8. Protocol Flow

### 8.1 User Requests A License

The user creates a license destination and delivers an issuance request to the LP through the request transport selected by the deployment, LP, payment flow, or application profile.

1. Generate a fresh license stealth address for the user:

   - sample `r_lic <- F_s`;
   - compute `R_lic = r_lic * G`;
   - compute `K_user = r_lic * pk_user.A`;
   - compute `lpk = H_SCALAR[CITADEL_STEALTH_DERIVE_V1](K_user) * G + pk_user.B`;
   - set `lsa = (lpk, R_lic)`.

2. Derive the license secret key:

   `lsk = H_SCALAR[CITADEL_STEALTH_DERIVE_V1](sk_user.a * R_lic) + sk_user.b`

   The user MUST keep `lsk` secret.

3. Derive or generate license encryption key material:

   `k_lic_enc = KDF[CITADEL_LICENSE_KEY_V1](lsk, lsa, deployment_id, salt_lic)`

   The KDF output MUST NOT be usable as `lsk`, and disclosure of `k_lic_enc` MUST NOT reveal `lsk`.

4. Generate a fresh request stealth address for the LP:

   - sample `r_req <- F_s`;
   - compute `R_req = r_req * G`;
   - compute `K_req = r_req * pk_lp.A`;
   - compute `rpk = H_SCALAR[CITADEL_STEALTH_DERIVE_V1](K_req) * G + pk_lp.B`;
   - set `rsa = (rpk, R_req)`.

5. Derive a request encryption key:

   `k_req = KDF[CITADEL_REQUEST_KEY_V1](K_req, rsa, pk_lp, deployment_id, salt_req)`

6. Encrypt `lsa || k_lic_enc || request_context` with AEAD under `k_req`, using associated data that includes the visible request fields and the transport-binding fields required by the deployment profile.

7. Deliver `Request { version, deployment_id, rsa, enc }` to the LP through one of the selected request transports, such as:

   - an authenticated and confidential off-chain channel;
   - an in-person handoff or QR code;
   - a payment transaction memo or equivalent transaction metadata field;
   - an authenticated off-chain availability layer or optional contract-backed request extension.

If the request is embedded in transaction metadata, the user MUST respect the transport's size and encoding limits. The user MUST NOT place `lsk`, `canonical_attributes`, disclosed attribute values, or `attr_opening` in the request or memo. The user SHOULD send an encrypted request object, or a request reference plus a hash, unless public-address or public-request disclosure is an explicit application choice for non-personal fields.

The request is not base contract state by default. It MUST NOT reveal the user's license secret key, `canonical_attributes`, disclosed attribute values, or `attr_opening`. Public or direct-issuance modes may intentionally reveal a static public key, account, payment, or routing context to the LP, but they do not permit personal data to be published on-chain or in contract-stored objects.

### 8.2 LP Processes A Request

The LP obtains candidate requests from the selected request transport. For payment-memo issuance, the LP MUST verify payment finality, payment recipient, asset, amount, memo or reference integrity, and binding to the relevant invoice, `request_id`, or `lsa` before issuance. For off-chain or in-person delivery, the LP MUST apply the authentication, confidentiality, and admission rules required by its profile.

For each candidate encrypted request:

1. Validate all encodings and size limits.
2. Compute `K_req = sk_lp.a * R_req`.
3. Check ownership of the request stealth address:

   `rpk == H_SCALAR[CITADEL_STEALTH_DERIVE_V1](K_req) * G + pk_lp.B`

4. Derive `k_req` with `CITADEL_REQUEST_KEY_V1`.
5. Attempt AEAD decryption. Failure means the request is not accepted.
6. Recover `lsa`, `k_lic_enc`, and request context.
7. Check the request replay policy.
8. Check that `deployment_id`, intended LP key, schema requests, visible request fields, and transport-binding fields match the decrypted context.
9. Evaluate any off-chain identity, payment, KYC, authorization, or business requirements.

The recovered `lsa` tells the LP where to issue the license. It does not reveal the user's static public key in the encrypted request path. Transport metadata, payment metadata, or application identity checks may still reveal the user to the LP.

### 8.3 LP Issues A License

If the request or direct-issuance input is accepted, the LP creates a license.

1. Define the attribute schema and `canonical_attributes` from the accepted eligibility process. If the attributes contain personal or user-specific data, the LP MUST NOT place those values in any contract-stored request, license, event, memo, or persistent availability payload.
2. Compute schema-scoped `attr_data` as specified by the schema. See Section 11.
3. Compute:

   `msg_lic = H[CITADEL_LICENSE_SIG_MSG_V1](lpk.u, lpk.v, attr_data)`

4. Sign `msg_lic` with the LP signing secret:

   `sig_lic = SchnorrSign(sk_lp.a, msg_lic)`

5. Encrypt `sig_lic || attr_data || pk_lp || license_context` under `k_lic_enc` or the deployment-defined direct-issuance license encryption key with AEAD and context-bound associated data. The included `pk_lp` MUST be the full canonical Phoenix public key whose `A` component verifies `sig_lic`. The plaintext MUST NOT include `canonical_attributes`, disclosed attribute values, or `attr_opening`.

6. Publish `License { version, deployment_id, lsa, enc }`.

7. Register the license with the contract:

   - the contract validates the visible license public key data;
   - the contract computes `license_hash`;
   - the contract checks issuance authorization or anti-spam policy;
   - the contract checks duplicate-license policy;
   - the contract inserts `license_hash` into the next available tree slot;
   - the contract records the new root under its root policy;
   - the contract stores the encrypted license blob for wallet discovery.

The LP MUST NOT reuse the same license stealth address for independent licenses unless the application explicitly wants those licenses to be linkable.

### 8.4 Direct Issuance

A deployment MAY support direct issuance without an encrypted request object. In direct issuance, the user provides a static public key, account identifier, `lsa`, or another deployment-defined issuance target to the LP through a payment flow, service flow, or in-person process.

When the user provides a static public key, the LP derives the license destination and license encryption material using DHKE with that public key. When the user provides an `lsa`, the user MUST also provide a license encryption mechanism that lets the LP encrypt the license without learning `lsk`. In all cases, the license encryption method MUST be deployment-defined and context-bound.

Direct issuance is a lower-privacy mode. The LP can know the user's static public key, account, payment identity, or in-person identity when issuing the license. Wallets and SPs SHOULD treat direct-issued licenses differently if issuer-verifier unlinkability matters.

### 8.5 User Fetches A License

The user scans stored encrypted licenses with `get_licenses`, optionally using `get_license` for direct lookup if it already knows a license tree position.

For each license:

1. Validate encodings and object version.
2. Check whether `lsa` belongs to the user by deriving the stealth secret.
3. Derive the applicable license decryption key.
4. AEAD-decrypt the encrypted payload.
5. Recover and validate the full `pk_lp` from the encrypted payload. Its canonical encoding MUST match the deployment's Phoenix public-key rules, and its `A` component is the LP signing point for this license.
6. Verify the LP signature over `msg_lic` using `pk_lp.A`, and compare `pk_lp` or `pk_lp.A` against the wallet's trusted issuer configuration according to the selected issuer-identifier rule.
7. Check that the decrypted `attr_data` matches the expected schema and deployment profile.
8. Verify that the computed `license_hash` is registered under an accepted root.
9. Record the license position, current accepted root, Merkle opening, `attr_data`, and full `pk_lp`.

The contract-stored license payload does not contain `canonical_attributes` or `attr_opening`. A user can use a selective-disclosure profile only if the wallet or user already has the underlying personal data and opening material needed by that schema, for example from local entry, local storage, or a non-chain issuance workflow.

The user SHOULD keep the newest valid license only if the application profile defines "newest wins". Otherwise, multiple licenses may be independently valid.

### 8.6 SP Publishes A Policy Profile

Before the user opens a session, the SP MUST define the policy it will enforce. This profile is application-specific.

At minimum, an SP profile MUST define:

- `policy_id` and policy version;
- accepted chain ID and contract ID;
- accepted `deployment_id`, circuit version, and verifier key hash;
- accepted generator set, domain constants, and Merkle parameters, if they are not implicit in the verifier key;
- SP public service point `pk_sp.A` or service identifier that cookies must bind to;
- accepted LP public keys or `pk_lp.A` signing points;
- accepted attribute schema IDs;
- attribute predicates or exact required values;
- challenge derivation and accepted `c` values;
- whether a cookie is one-time, reusable, account-bound, channel-bound, client-key-bound, or SP-nonce-bound;
- root freshness requirements, if stricter than the contract;
- expiration and revocation requirements;
- selective-disclosure proof requirements, if base disclosure is not used.

The SP MAY choose any challenge and authorization policy that fits its service, but it MUST NOT accept arbitrary user-chosen `c` values if it relies on Citadel for single-use, rate-limited, epoch-limited, event-limited, account-bound, or nonce-bound access.

Recommended challenge template:

`c = H[CITADEL_POLICY_CHALLENGE_V1](deployment_id, sp_id, service_id, policy_id, epoch_or_event_id, sp_nonce)`

This template is a recommendation, not a universal requirement. The mandatory requirement is that the SP defines exactly which `c` values it accepts and verifies the cookie opening for `com_2` against that rule.

### 8.7 User Opens An On-Chain Session

To open a session, the user first performs local computations outside the circuit:

- `lsk`: license secret key. This value MUST stay outside the circuit and MUST NOT be shared with a proof helper.
- `lpk = lsk * G`: license public key, equal to `lsa.lpk`.
- `lpk_p = lsk * G'`: secondary license public key.

The user prepares the remaining private witness values:

- `sig_lic`: LP signature on `msg_lic`.
- `pk_lp.A`: LP signing point.
- `attr_data`: signed schema-scoped attribute value. For schemas containing personal or user-specific data, this is a digest of `canonical_attributes`, not the raw attributes.
- `c`: SP policy challenge value.
- `r_session`: fresh session randomness. It MUST NOT be reused with the same `pk_sp.A`; reuse can make sessions linkable.
- `s_0`, `s_1`, `s_2`: fresh commitment randomness.
- Merkle opening for `license_hash`.

The user computes:

- `session_hash = H[CITADEL_SESSION_HASH_V1](pk_sp.A.u, pk_sp.A.v, r_session)`
- `session_id = H[CITADEL_SESSION_ID_V1](lpk_p.u, lpk_p.v, c)`
- `com_0 = H[CITADEL_LP_COMMITMENT_V1](pk_lp.A.u, pk_lp.A.v, s_0)`
- `com_1 = attr_data * G + s_1 * G'`
- `com_2 = c * G + s_2 * G'`
- `session_auth = H[CITADEL_SESSION_AUTH_V1](session_id, session_hash, com_0, com_1.x, com_1.y, com_2.x, com_2.y, root)`
- `sig_session_auth = DoubleSchnorrSign(lsk, session_auth)`

The double-key signature authorizes the exact public session tuple. This prevents a proof helper from reusing a signature to submit a different challenge, root, or commitment tuple.

The user generates a PlonK proof for the license circuit and submits:

- `proof`
- `public_inputs = [session_id, session_hash, com_0, com_1.x, com_1.y, com_2.x, com_2.y, root]`

### 8.8 Contract Verifies License Use

On `use_license`, the contract MUST:

1. Validate public input length and canonical field encodings.
2. Verify the PlonK proof with the deployment verifier key.
3. Check that `root` is accepted under the deployment root policy.
4. Reject if `session_id` already exists.
5. Store the session under `session_id`.

The duplicate-session check is the on-chain nullifier mechanism. It only prevents duplicate sessions for the same hidden license and the same accepted challenge value. It does not prevent repeated off-chain use of the same cookie.

The duplicate check and session insertion MUST be atomic with proof acceptance.

The contract MAY enforce additional deployment policy, but it does not need to know SP identity, LP identity, attributes, or challenge value in the base protocol.

### 8.9 User Requests Service Off-Chain

The user opens an authenticated and confidential channel to the SP and sends the base session cookie or the selective-disclosure variant required by the SP profile.

The channel MUST authenticate the SP endpoint. The cookie MUST NOT be sent over an unauthenticated or plaintext channel.

### 8.10 SP Verifies The Cookie

The SP fetches the session by `session_id` from authenticated and sufficiently finalized contract state. It verifies that the session belongs to the expected deployment, contract, and circuit version.

The fetched session provides the public `session_id`, `session_hash`, `com_0`, `com_1`, `com_2`, and `root` values that the cookie must open.

For the base disclosure cookie, the SP MUST verify:

1. The session exists.
2. The fetched public input vector has the expected length and canonical encodings, and `com_1` and `com_2` decode to valid non-identity Jubjub points.
3. The cookie `deployment_id`, `version`, `cookie_mode`, and `policy_id` match the selected SP profile.
4. The cookie `session_id` equals the fetched session ID.
5. `pk_sp.A` equals the SP public service point for this profile.
6. `H[CITADEL_SESSION_HASH_V1](pk_sp.A.u, pk_sp.A.v, r_session) == session.session_hash`.
7. `H[CITADEL_LP_COMMITMENT_V1](pk_lp.A.u, pk_lp.A.v, s_0) == session.com_0`.
8. `attr_data * G + s_1 * G' == session.com_1`.
9. `c * G + s_2 * G' == session.com_2`.
10. `pk_lp` or `pk_lp.A`, according to the profile identifier rule, is in the SP's accepted issuer set for this policy.
11. `attr_data` satisfies the SP's accepted schema and attribute policy. If `attr_data` is a digest, the user must either disclose the required attributes and opening material over the off-chain service channel or provide the selective-disclosure proof required by the profile. The SP MUST NOT infer attribute semantics from the contract-stored license payload, because it contains only the digest and non-personal metadata.
12. `c` exactly matches the SP's challenge policy.
13. The session root satisfies the SP's freshness policy.
14. Expiration and revocation requirements are satisfied.
15. Cookie replay, account binding, channel binding, client-key binding, and rate-limit checks pass.

Only after all required checks pass MAY the SP grant service.

The SP MUST record cookie, nonce, account, or session consumption if service is intended to be one-time. For reusable service, the SP MUST define reuse limits explicitly.

## 9. License Circuit

The license circuit proves knowledge of private values satisfying the statements below.

`deployment_id`, generator choices, domain constants, signature transcripts, and Merkle parameters are fixed deployment constants for this circuit version unless a future circuit version explicitly makes them public inputs.

Public inputs:

- `session_id`
- `session_hash`
- `com_0`
- `com_1.x`
- `com_1.y`
- `com_2.x`
- `com_2.y`
- `root`

Private witnesses:

- `lpk`
- `lpk_p`
- `sig_lic`
- `pk_lp.A`
- `attr_data`
- `c`
- `s_0`
- `s_1`
- `s_2`
- `sig_session_auth`
- Merkle opening

`canonical_attributes` and `attr_opening` are not witnesses in the base license circuit. They are used only by off-chain base-cookie opening or by a separate selective-disclosure proof profile.

`lpk` and `lpk_p` are private witness points. The circuit does not compute `lpk = lsk * G` or `lpk_p = lsk * G'`, and `lsk` is not a circuit witness. The relation between `lpk`, `lpk_p`, and the user's license secret is proved by the double-key Schnorr verification.

The circuit enforces:

1. Private witness points used as public keys or commitments are valid non-identity points in the intended subgroup.

2. The session ID is correctly derived:

   `session_id = H[CITADEL_SESSION_ID_V1](lpk_p.u, lpk_p.v, c)`

3. The LP signature verifies:

   - message is `msg_lic = H[CITADEL_LICENSE_SIG_MSG_V1](lpk.u, lpk.v, attr_data)`;
   - `sig_lic` verifies under `pk_lp.A` with the `CITADEL_LICENSE_SIG_CHALLENGE_V1` transcript.

4. The user knows the license secret key corresponding to both private witness points:

   - `session_auth = H[CITADEL_SESSION_AUTH_V1](session_id, session_hash, com_0, com_1.x, com_1.y, com_2.x, com_2.y, root)`;
   - `sig_session_auth` is a valid double-key Schnorr signature over `session_auth` with the `CITADEL_SESSION_SIG_CHALLENGE_V1` transcript;
   - the public keys used by double-key verification are `(lpk, lpk_p)`;
   - the double-key statement proves knowledge of the same scalar for `G` and `G'`.

5. The LP commitment opens:

   `com_0 = H[CITADEL_LP_COMMITMENT_V1](pk_lp.A.u, pk_lp.A.v, s_0)`

6. The attribute commitment opens:

   `com_1 = attr_data * G + s_1 * G'`

7. The challenge commitment opens:

   `com_2 = c * G + s_2 * G'`

8. The license leaf is in the license Merkle tree:

   - `license_hash = H[CITADEL_LICENSE_HASH_V1](lpk.u, lpk.v)`;
   - the private Merkle path opens `license_hash` under public `root`.

The circuit does not prove that the SP trusts `pk_lp` or `pk_lp.A`, that attributes satisfy a service policy, that `session_hash` opens to the SP's configured `pk_sp.A`, that `c` is accepted by the SP, that the cookie was not replayed, or that a license has not been revoked unless those checks are added by a deployment-specific extension.

## 10. Challenge And Reuse Semantics

The challenge `c` controls nullification.

For a fixed license secret and a fixed `c`, `session_id` is deterministic. The contract rejects a second session with the same `session_id`.

If the SP accepts arbitrary `c` values, a user can create many distinct sessions from the same license. This is not a cryptographic failure; it is an SP policy failure.

Common profiles:

- **Single-use forever:** `c` is a fixed constant for the service policy.
- **Once per event:** `c` is derived from event ID and policy ID.
- **Once per epoch:** `c` is derived from epoch or date.
- **SP-nonce gated:** `c` includes a fresh SP nonce and the SP records that nonce or session as consumed.
- **Account-bound access:** `c` or the SP's replay table binds the session to an authenticated account or client key.
- **Channel-bound access:** the cookie is accepted only inside a channel whose binding data is checked by the SP profile.

These are examples. SPs MAY define other profiles, but they MUST be exact and verifiable.

## 11. Attributes And Disclosure

### 11.1 Canonical Attributes, Openings, And `attr_data`

`canonical_attributes` are the schema-defined attribute values about the user or license holder. They can include personal data, eligibility facts, validity intervals, revocation handles, or other claims that an LP evaluates and signs. Each schema defines the exact canonical serialization, normalization rules, field order, type tags, and byte-to-field or hash-to-field mapping for these values.

`attr_data` is the value signed by the LP and committed in the on-chain session. For every schema that contains personal or user-specific data, `attr_data` MUST be a schema-scoped digest of `canonical_attributes`, not a direct encoding of the personal data:

`attr_data = H[CITADEL_ATTR_DATA_V1](schema_id, canonical_attributes, r_attr)`

where `r_attr` is fresh attribute blinding randomness or another schema-defined opening secret. If `canonical_attributes` are larger than the native Poseidon input capacity, the schema MUST define a canonical chunking, Merkleization, or prehashing rule before this digest is computed. The resulting `attr_data` MUST be represented as a canonical scalar or field element before it is signed, committed, or used in a circuit.

The following privacy rule is normative for all conforming base deployments: `canonical_attributes`, disclosed attribute values, and `attr_opening` MUST NOT appear in blockchain-published data, contract state, contract events, payment memos, request-availability payloads, or contract-stored encrypted license blobs, whether plaintext or encrypted. The only attribute-derived values that may appear in those places are schema-scoped hashes, commitments, or digests such as `attr_data`; public sessions store only `com_1`, a Pedersen commitment to `attr_data`.

This means the contract-stored encrypted license is not an encrypted online backup of the user's personal data. A license recipient can later use a selective-disclosure profile only if the recipient already knows the relevant `canonical_attributes` and has the opening material required by the schema, such as `r_attr`. Wallets SHOULD store `attr_opening` locally or derive it deterministically from local secrets and issuance context. They MUST NOT rely on recovering personal data from the contract-stored license payload.

Every supported attribute schema MUST define:

- schema ID and version;
- canonical serialization and normalization rules for `canonical_attributes`;
- byte-to-field, chunking, Merkleization, or hash-to-field mapping;
- required and optional fields;
- which fields are personal or user-specific;
- issuer scope;
- service or policy scope, if applicable;
- issuance time, expiration time, or explicit no-expiration marker;
- revocation handle or explicit no-revocation marker, if applicable;
- how `r_attr` or equivalent opening material is generated, stored, and used;
- privacy mode: base disclosure or selective disclosure.

A directly encoded `attr_data` scalar is permitted only for non-personal, non-user-specific schema values whose semantics are unambiguous from the schema and SP profile, such as a coarse public license class. It MUST NOT be used for names, identifiers, dates of birth, addresses, contact data, biometric data, account identifiers, unique membership numbers, or other personal or linkable user-specific fields.

In base disclosure mode, `attr_data` is disclosed to the SP. If `attr_data` is a digest, the SP cannot check the underlying attribute semantics unless the user also discloses the necessary `canonical_attributes` and `attr_opening` over the off-chain service channel, or provides a selective-disclosure proof. Base disclosure of personal data is an intentional off-chain disclosure to that SP profile and MUST NOT be submitted to the blockchain.

Because the LP knows the `attr_data` it signed, base disclosure of `attr_data` can be a stable correlation handle if the LP and SP collude. A profile that needs issuer-verifier unlinkability SHOULD use selective disclosure or another profile that does not reveal an LP-known value to the SP.

Attributes SHOULD include expiration or validity information unless the license is intentionally permanent. If expiration or revocation fields are personal or user-specific, they follow the same digest-and-disclose/prove rule as other attributes.

### 11.2 Selective Disclosure

For privacy-sensitive services, an SP SHOULD use a selective-disclosure profile. In this mode, the SP learns only the disclosed attributes and predicate result defined by its profile; it does not learn `attr_data`, `s_1`, hidden attributes, or hidden opening material unless the profile explicitly discloses them.

A selective-disclosure profile defines an off-chain proof with public inputs such as:

- `com_1` from the on-chain session;
- `session_id`;
- `deployment_id`;
- `schema_id`;
- `policy_id`;
- disclosed attributes, if any;
- SP challenge or nonce, if needed;
- cookie mode and proof version.

The private witnesses include:

- hidden `canonical_attributes`;
- `r_attr` or equivalent `attr_opening`;
- `attr_data`;
- `s_1`.

The proof MUST show:

1. `attr_data = H[CITADEL_ATTR_DATA_V1](schema_id, canonical_attributes, r_attr)`, or the schema-defined equivalent digest construction.
2. `com_1 = attr_data * G + s_1 * G'`.
3. The attributes satisfy the SP's predicate.
4. Any disclosed attributes are consistent with the hidden committed attributes.
5. The proof is bound to the intended session, deployment, policy profile, cookie mode, and SP challenge or nonce.

LPs and SPs MUST agree on the schema and predicate circuit. A generic Citadel session verifier cannot infer selective-disclosure semantics without that profile.

## 12. Revocation, Expiration, And Replay

### 12.1 Revocation And Current Validity

The base registry is append-only membership. It proves that a license was registered under an accepted root. It does not prove that the license is still valid unless the deployment or SP profile adds such a rule.

Deployments and SPs MUST NOT claim revocation support unless they implement one of the following:

- expiration or validity interval committed by `attr_data` and either disclosed or proven to the SP;
- SP-maintained deny list keyed by session, account, disclosed credential, or other application identifier;
- contract-maintained revocation or status accumulator with a circuit proof of non-revocation;
- epoch-specific roots with strict root freshness and migration rules.

If revocation is security-critical, an SP-side deny list alone may be insufficient because base sessions hide the license key. The deployment SHOULD use a protocol-level status mechanism or attributes that reveal only the minimum identifier needed for revocation under the service's privacy model.

Old accepted roots can bypass revocation if the revocation design is not bound to root freshness. Root age and status checks MUST be designed together.

If expiration or revocation status is hidden inside an attribute digest and is neither disclosed nor proven in a selective-disclosure proof, the SP has not enforced expiration or revocation.

### 12.2 Cookie Replay And Binding

A base session cookie is a bearer credential. The on-chain nullifier prevents duplicate session creation, not duplicate service use.

Each SP profile MUST define at least one of:

- one-time cookie use, with server-side consumption state;
- reusable cookie use, with explicit limits;
- channel-bound cookie use;
- account-bound cookie use;
- client-key-bound cookie use;
- SP-nonce-bound cookie use.

Recommended one-time profile:

1. SP issues a fresh nonce and policy ID.
2. User derives `c` from `deployment_id`, SP ID, service ID, policy ID, and nonce.
3. User opens a session and sends the cookie.
4. SP verifies the cookie and atomically marks the nonce or `session_id` consumed.
5. Future use of the same nonce or `session_id` is rejected.

For long-lived sessions, the SP SHOULD bind access to an authenticated account or client-held key and set a clear expiration.

## 13. Privacy Properties And Limits

### 13.1 On-Chain Observers

On-chain observers see:

- request payloads, payment memos, transaction notes, or request references when the selected transport publishes them on-chain;
- encrypted license blobs, which in a conforming deployment contain `attr_data`, `pk_lp`, signatures, and non-personal metadata, but not `canonical_attributes` or `attr_opening`;
- license stealth addresses;
- license hashes;
- Merkle roots;
- session public inputs, including `com_1` as a commitment to `attr_data`;
- transaction timing and fees.

They should not learn:

- which license was used in a session;
- the user wallet public key;
- the LP public key used in the proof;
- the SP public key used in the session;
- signed personal attributes or `canonical_attributes`;
- `attr_data` from session records, except if the user later discloses it off-chain or a nonconforming deployment publishes it;
- challenge value;
- Merkle path.

These privacy properties rely on fresh randomness, valid commitments, PlonK zero knowledge, domain separation, and users not reusing stealth secrets, commitment randomness, or session randomness.

### 13.2 LP And SP Knowledge

The LP learns whatever the user discloses during license request review, payment processing, direct handoff, and the attributes it signs. In encrypted request-based issuance, the LP does not learn the user's static public key from the cryptographic request alone unless the request context, payment channel, network metadata, or business process reveals it.

The SP learns whatever is disclosed by the selected cookie mode and policy proof. In base mode, it learns `attr_data` and, when required by the profile, any attributes and opening material the user intentionally discloses over the off-chain service channel. In selective-disclosure mode, it learns only the disclosed attributes and predicate results defined by the profile.

If the LP also knows a disclosed `attr_data` value, that value itself can link issuance and service use under LP/SP collusion. Selective-disclosure profiles avoid revealing `attr_data` to the SP unless the profile deliberately makes it public.

If the LP and SP collude, unique attributes, request metadata, payment memo metadata, timing, payments, network metadata, or direct issuance can link issuance to service use. Citadel does not prevent correlation through non-cryptographic side channels.

### 13.3 Proof Helpers

A user MAY delegate proof generation to a proof helper without revealing `lsk`. The helper MUST NOT receive `lsk`; the user computes `sig_session_auth` locally and sends the helper only the resulting signature and the other proving inputs needed by the circuit.

The helper may still learn sensitive metadata, including which license leaf and LP are involved, unless additional blinding or local proving is used.

Proof-helper delegation is an operational choice and must be evaluated under the user's privacy requirements.

## 14. Security Assumptions

Citadel relies on:

- discrete-log hardness in the selected Jubjub subgroup;
- binding and hiding properties of Pedersen commitments with independent generators;
- collision resistance and circuit-appropriate security of Poseidon with proper domain separation;
- Schnorr signature unforgeability under the specified transcripts;
- soundness and zero knowledge of the deployed PlonK circuit and verifier key;
- correct PlonK setup or verifier-key generation according to the deployment's proof-system assumptions;
- AEAD confidentiality and integrity;
- correct DHKE and KDF use;
- fresh randomness;
- canonical encoding, scalar range checks, and point validation;
- contract root anchoring;
- authenticated and sufficiently finalized contract-state reads by wallets, LPs, and SPs;
- SP enforcement of issuer, attribute, challenge, replay, revocation, and service policy.

If any of these assumptions does not hold, the affected security property does not hold.

## 15. Conformance Checklist

A deployment conforms to this specification only if:

- every Poseidon, KDF, and signature context is domain-separated;
- every external point and scalar is canonically validated;
- circuit witness points are constrained to valid non-identity subgroup points;
- request-object encryption, when used, and license encryption are authenticated and context-bound;
- contract-stored licenses include the full canonical `pk_lp`, and `pk_lp.A` matches the LP signature verification key;
- blockchain-published requests, payment memos, availability payloads, contract events, and contract-stored encrypted license blobs do not contain `canonical_attributes`, disclosed attribute values, or `attr_opening`, whether plaintext or encrypted;
- request transport, replay handling, payment binding, retention, duplicate handling, size limits, fees, and spam controls are explicit when request objects are used;
- gas-only spam control, if used for license insertion or an optional request-availability extension, is explicitly justified by deployment economics and operational cost assumptions;
- license hashes are derived from visible license public key data;
- issuance access and tree-capacity behavior are explicit;
- duplicate `license_hash` handling is explicit;
- Merkle roots in license-use proofs are checked against contract-accepted roots;
- wallets, LPs, and SPs use authenticated contract state with the deployment's finality policy;
- public input order is fixed and versioned;
- the double-key session authorization signature binds the exact public input tuple;
- duplicate `session_id` values are rejected atomically;
- SP profiles define exact challenge validation;
- cookies identify `policy_id` and cookie mode explicitly;
- SPs verify that `pk_sp.A` in a cookie is their configured service point for the selected policy;
- SPs treat cookies as bearer credentials unless they add binding;
- selective-disclosure proofs are bound to the intended session, deployment, policy, cookie mode, and SP challenge or nonce;
- expiration and revocation are not claimed unless implemented by the profile;
- attribute schemas are canonical, schema-scoped, versioned, and explicit about which fields are personal or user-specific;
- direct issuance is marked as a lower-privacy mode.

## 16. Minimal Safe Deployment Guidance

For an academic or prototype deployment:

- use encrypted request-based issuance unless direct issuance privacy tradeoffs are acceptable;
- deliver requests through the payment, service, or authenticated off-chain channel instead of the base contract;
- set maximum request payload, payment-memo, request-reference, and license blob sizes;
- define request-transport admission, replay, payment-binding, and spam controls;
- allow-list LP issuers or require fees for registry insertion;
- keep a bounded root history;
- use base disclosure only for non-sensitive attributes;
- do not store encrypted personal data in request objects, payment memos, availability payloads, or license blobs that are written to the blockchain or otherwise published as persistent online protocol data;
- use fixed or policy-derived challenges bound to deployment, SP, service, and policy context, never arbitrary user challenges;
- treat cookies as one-time unless the service is explicitly reusable;
- include expiration in attributes and require wallets to keep any `attr_opening` needed for later disclosure or selective-disclosure proofs;
- document that protocol-level revocation is not available unless a status extension is deployed.

For production deployments, Citadel should undergo implementation review, circuit review, verifier-key review, dependency review, deployment-parameter review, contract-state economics review, and operational security review in addition to this protocol specification.
