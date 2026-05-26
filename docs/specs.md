# Citadel Protocol Specification

**Updated:** 26 May 2026. 

**Status:** Draft.

Citadel lets a user obtain an encrypted license from a License Provider (LP),
prove on-chain that the license exists without revealing it, and then disclose a
session cookie to a Service Provider (SP). The protocol deliberately separates
cryptographic validity from service authorization: the contract verifies the
zero-knowledge proof and records a session, while each SP decides whether that
session satisfies its own policy.

This document is normative for the Citadel protocol shape. SP choices such as
accepted issuers, attribute predicates, challenge format, replay handling,
revocation, expiration, and rate limits are policy profile inputs, not universal
protocol constants.

The terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as
described in RFC 2119 and RFC 8174 when, and only when, they appear in
uppercase.

## 1. Scope

Citadel provides the following base guarantees:

- A user can prove possession of a license secret key without revealing it.
- A user can prove that the hidden license public key is registered in the
  contract's license tree under an accepted Merkle root.
- An LP signature binds the issued attributes to the license public key.
- Public session data does not reveal the user wallet key, license public key,
  LP key, SP key, attributes, challenge, signature, or Merkle path.
- The same hidden license cannot create two accepted sessions for the same
  SP-accepted challenge value.
- An SP can verify that a cookie opens the public on-chain session values.

Citadel does not, by itself, grant service access. The SP must still check
issuer trust, attributes, challenge acceptance, replay rules, root freshness,
revocation, expiration, account binding, and rate limits.

Citadel also does not automatically provide:

- replay protection for a disclosed cookie;
- revocation or current-validity checks beyond membership in an accepted root;
- issuer-verifier unlinkability when attributes are unique or the LP and SP
  collude;
- authorization for every service that accepts Citadel proofs.

## 2. Core Concepts

### 2.1 Parties

- User: controls a wallet key pair, requests licenses, owns license secret keys,
  opens sessions, and sends cookies to SPs.
- License Provider (LP): evaluates requests, defines signed attributes, signs
  licenses, and publishes encrypted licenses.
- Service Provider (SP): publishes an authorization policy, verifies cookies,
  and grants or denies service.
- Contract: stores issued license commitments, maintains accepted Merkle roots,
  verifies license-use proofs, rejects duplicate session IDs, and stores public
  session records.
- Validators: execute the contract and verify proofs according to the deployed
  verifier key.

The LP and SP MAY be the same legal or operational entity, but the protocol
treats them as separate roles. If they are the same entity, privacy guarantees
against issuer-verifier correlation are weaker.

### 2.2 Identifiers And Secrets

The following names are used throughout the specification:

- `pk = (A, B)`: Phoenix-style public key.
- `pk_user`, `pk_lp`, `pk_sp`: role-specific Phoenix public keys for the user,
  LP, and SP.
- `sk = (a, b)`: matching Phoenix-style secret key.
- `lsa`: license stealth address. This is the public destination where an LP
  issues an encrypted license.
- `lsk`: one-time license secret key derived by the user for `lsa`.
- `lpk = lsk * G`: one-time license public key, equal to the public key carried
  by `lsa`.
- `lpk_p = lsk * G'`: secondary license public key used only for nullification
  and double-key authorization.
- `pk_lp.A`: LP signing point used to verify the license signature.
- `pk_sp.A`: SP service point that a cookie is bound to.
- `attr_data`: canonical scalar or field digest representing the attributes the
  LP signed.
- `c`: SP policy challenge value. It controls nullification and reuse.
- `root`: accepted Merkle root of the license registry.
- `session_id`: public nullifier derived from `lpk_p` and `c`.
- `session_hash`: public commitment tying a session cookie to `pk_sp.A` and
  fresh session randomness.
- `com_0`: commitment to `pk_lp.A`.
- `com_1`: Pedersen commitment to `attr_data`.
- `com_2`: Pedersen commitment to `c`.

The circuit receives `lpk` and `lpk_p` as private witness points. It does not
receive `lsk` and does not compute either point from `lsk`; instead it verifies
a double-key Schnorr authorization proving knowledge of the same hidden scalar
for both points.

### 2.3 Data Objects

Citadel uses four main data objects:

- Request: encrypted message from a user to an LP asking for issuance to a
  license stealth address.
- License: encrypted LP-signed asset published to the user and registered in
  the license tree as `license_hash`.
- Session: public on-chain record created after a successful license-use proof.
- Cookie: off-chain disclosure from the user to the SP that opens selected
  public session commitments.

### 2.4 Lifecycle

The normal request-based flow is:

1. The user creates `lsa`, derives `lsk`, and sends an encrypted request to the
   LP.
2. The LP decrypts the request, evaluates its own issuance policy, signs
   `attr_data` for `lpk`, publishes an encrypted license, and registers
   `license_hash` in the contract tree.
3. The user finds the license, decrypts it, verifies the LP signature, and
   obtains a Merkle opening for `license_hash`.
4. The SP publishes or communicates a policy profile, including accepted LPs,
   attributes, challenge rules, and replay rules.
5. The user creates a license-use proof for that policy challenge `c` and
   submits it to the contract.
6. The contract verifies the proof, checks `root`, rejects duplicate
   `session_id` values, and stores the public session.
7. The user sends the SP a base or selective-disclosure cookie.
8. The SP fetches the on-chain session, verifies the cookie openings, and then
   applies its policy.

## 3. Threat Model

### 3.1 Assets

- User wallet secret keys and derived license secret keys.
- LP signing keys and issuance policy decisions.
- SP service access decisions.
- License attributes and eligibility claims.
- Session cookies and commitment openings.
- Merkle tree state, roots, and openings.
- Contract verifier key and circuit definition.
- Privacy of which issued license was used in a session.
- Availability of the license registry and session registry.

### 3.2 Adversaries

- Passive chain observer: sees license blobs, license hashes, roots, public
  session inputs, and timing.
- Network observer: sees off-chain communication unless the channel is
  authenticated and confidential.
- Malicious user: tries to forge, reuse, transfer, replay, or overuse access.
- Malicious LP: signs false attributes, issues outside policy, spams the
  registry, or correlates issuance records with later disclosures.
- Malicious SP: accepts weak challenges, tracks users, leaks cookies, or skips
  required policy checks.
- LP/SP collusion: combines issuance records, attribute uniqueness, cookie
  disclosures, and service metadata to deanonymize users.
- State spammer: attempts to fill the Merkle tree, store bogus licenses, or
  force expensive proof verification.
- Key-compromise adversary: obtains user, LP, SP, or service-channel keys.

### 3.3 Trust Assumptions

- The LP is trusted only for the correctness of attributes it signs. An SP MUST
  decide which LP public keys it trusts.
- The SP is trusted by the user with any attributes or openings disclosed in the
  selected service profile.
- The contract verifier key, circuit definition, domain constants, Merkle depth,
  and root-acceptance rules are correct for the deployment.
- Poseidon, Schnorr, Pedersen commitments, DHKE, AEAD encryption, and PlonK are
  implemented correctly and with valid parameters.
- Randomness for stealth addresses, signatures, commitments, encryption, and
  session creation is generated by a CSPRNG.
- All externally supplied encodings are validated canonically before use.
- Wallets and SPs read contract state from an authenticated source and apply the
  deployment's finality or reorganization policy before relying on a root or
  session.

## 4. Deployment And Encoding Requirements

### 4.1 Deployment Parameters

Each Citadel deployment MUST define:

- protocol version;
- chain ID;
- contract ID;
- compact deployment ID;
- verifier key and circuit hash;
- generator set;
- Poseidon domain constants;
- compact hash context derivation;
- Merkle tree parameters;
- root acceptance policy;
- license issuance access policy;
- tree-full behavior;
- supported attribute schemas;
- supported SP policy profiles, if any are published by the deployment;
- chain-finality requirements for wallets and SPs;
- upgrade and deprecation rules for protocol, circuit, domain, and parameter
  changes.

The contract MUST expose enough metadata for wallets and SPs to verify that they
are using the intended verifier key, tree parameters, and root policy.

For circuit efficiency, deployment metadata is represented in protocol objects
by one field element, `deployment_id`. The deployment profile defines how this
identifier is assigned or derived from the protocol version, chain ID, contract
ID, verifier key, and other deployment parameters. Domain separation metadata is
then compressed into one field element per logical hash domain:

`ctx_D = PoseidonOther(CITADEL_CONTEXT_V1, deployment_id, domain_id_D)`

where `domain_id_D` is the fixed identifier for domain `D`. Circuit hash
preimages MUST use `ctx_D` as their first element instead of absorbing
`domain_id_D`, version, chain, or contract values separately. The uncompressed
deployment metadata remains part of the deployment metadata, but the compact
`deployment_id` is the value carried by requests, licenses, session cookies, and
the circuit context.

Any change to public input order, hash preimages, domain constants, generator
set, Merkle parameters, signature messages, KDF inputs, or verifier key defines
a new protocol or circuit version. Implementations MUST NOT silently mix data
from different versions.

### 4.2 Canonical Encoding

Every externally supplied value MUST be validated before cryptographic use.

For Jubjub points, implementations MUST:

- require canonical byte encoding;
- reject decoding failures;
- check that the point is on the curve;
- check that the point is in the prime-order subgroup;
- reject the identity point unless a specific protocol field explicitly allows
  it;
- compare trust-list entries using canonical encodings.

For scalar field elements, implementations MUST:

- require canonical field encoding;
- reject out-of-range values;
- reject ambiguous byte encodings;
- define a deterministic byte-to-field mapping for hashes of structured data.

For structured data, implementations MUST:

- use versioned canonical serialization;
- avoid ad hoc concatenation without lengths or type tags;
- bind the `deployment_id` and schema ID where relevant.

These validation rules apply to requests, licenses, public inputs, cookies, LP
keys, SP keys, Merkle openings, signatures, and off-chain predicate proof
inputs.

## 5. Cryptographic Building Blocks

### 5.1 Groups And Fields

Citadel uses:

- BLS12-381 for PlonK and scalar-field arithmetic.
- Jubjub's prime-order subgroup for Phoenix-style keys, stealth addresses,
  Schnorr signatures, and Pedersen commitments.

Let `F` be the scalar field used by the circuit. Let `J` be the prime-order
Jubjub subgroup. Let `G` and `G'` be independent fixed generators of `J`.

The discrete logarithm of `G'` with respect to `G` MUST be unknown. The
generators MUST be fixed by the deployment and included in the audited circuit
definition. The same generator set MUST be used by wallets, LPs, SPs, and the
contract verifier.

### 5.2 Phoenix-Style Keys

Each party uses:

- Secret key: `sk = (a, b)` where `a, b in F`.
- Public key: `pk = (A, B)` where `A = aG` and `B = bG`.

The `A` component is used for DHKE and signing where specified. The `B`
component is used in stealth-address derivation. Public keys MUST be canonical
Jubjub points and MUST pass the validation rules in Section 4.2.

Role-specific keys are written as `sk_user`, `pk_user`, `sk_lp`, `pk_lp`,
`sk_sp`, and `pk_sp`. Public-key names always refer to full Phoenix public
keys. When a formula needs the signing, service, or DHKE point, it names the
component explicitly, for example `pk_lp.A`, `pk_sp.A`, or `pk_user.A`.
Profiles MUST state whether an issuer or service is identified by a full
Phoenix public key, by its `A` component, or by another deployment identifier,
and all comparisons MUST use canonical encodings.

### 5.3 Domain-Separated Hashes

Poseidon is used for values that must be reproduced inside the circuit. Every
Poseidon use MUST be domain-separated. The deployment MUST publish fixed field
constants for every domain tag used by the circuit and by off-chain
verification.

This specification writes a domain-separated hash as:

`H[DOMAIN](x_0, ..., x_n)`

For domains that are used inside the base circuit, this notation means:

`H(ctx_DOMAIN, x_0, ..., x_n)`

where `ctx_DOMAIN` is the compact context scalar defined in section 4.1.
Merkle internal nodes are the exception: they use the fixed Poseidon
`Merkle4` domain for exactly four children.

When a scalar output is required from a point or byte string, the canonical
encoding is mapped to field elements before hashing:

`H_SCALAR[DOMAIN](...)`

Required domains:

- `CITADEL_CONTEXT_V1`
- `CITADEL_STEALTH_DERIVE_V1`
- `CITADEL_REQUEST_KEY_V1`
- `CITADEL_LICENSE_KEY_V1`
- `CITADEL_LICENSE_HASH_V1`
- `CITADEL_LICENSE_SIG_MSG_V1`
- `CITADEL_SESSION_HASH_V1`
- `CITADEL_SESSION_AUTH_V1`
- `CITADEL_SESSION_ID_V1`
- `CITADEL_LP_COMMITMENT_V1`
- `CITADEL_ATTR_DATA_V1`
- `CITADEL_REQUEST_ID_V1`
- `CITADEL_POLICY_CHALLENGE_V1`

A deployment MAY define additional domains for new circuits or SP policy
profiles. It MUST NOT reuse the same domain for different semantic objects.

### 5.4 Stealth Addresses

A Citadel stealth address contains a one-time public key and a sender public
nonce:

`sa = (opk, R)`

where:

- `r <- F` is fresh sender randomness;
- `R = rG`;
- `k = r * pk_recipient.A`;
- `opk = H_SCALAR[CITADEL_STEALTH_DERIVE_V1](k) * G + pk_recipient.B`.

The recipient detects ownership by computing `k = sk_recipient.a * R` and
checking that:

`opk = H_SCALAR[CITADEL_STEALTH_DERIVE_V1](k) * G + pk_recipient.B`

The recipient's one-time secret key is:

`nsk = H_SCALAR[CITADEL_STEALTH_DERIVE_V1](k) + sk_recipient.b`

For a license stealth address `lsa`, Citadel names the one-time public key
`lpk`. For a request stealth address `rsa`, Citadel names it `rpk`. Phoenix
terminology for this field is intentionally avoided here.

Fresh `r` MUST be used for every stealth address. Reusing stealth randomness or
one-time secrets can link licenses and can break privacy.

### 5.5 Signatures

Citadel uses Jubjub Schnorr signatures:

- single-key Schnorr for LP license signatures;
- double-key Schnorr for proving license-secret possession while binding both
  `lpk` and `lpk_p`.

Schnorr challenge hashes MUST be domain-separated by protocol purpose and MUST
include canonical encodings of the public key, nonce points, message, and
protocol version. LP signing keys SHOULD NOT be reused for unrelated protocols
unless all signing contexts are strongly domain-separated.

Schnorr signing nonces MUST be generated with a CSPRNG or by a deterministic
nonce derivation that is domain-separated and binds the signing secret, public
key, message, and protocol context. A signing nonce MUST NOT be reused with the
same signing key.

The double-key Schnorr statement MUST prove knowledge of one scalar `x` such
that `lpk = xG` and `lpk_p = xG'`. Verification MUST bind both public keys, all
nonce points, the message, and the signature domain.

### 5.6 Commitments

Citadel uses:

- a Poseidon hash commitment for the LP public signing point:

  `com_0 = H[CITADEL_LP_COMMITMENT_V1](pk_lp.A.u, pk_lp.A.v, s_0)`

- Pedersen commitments for scalar values:

  `com_1 = attr_data * G + s_1 * G'`

  `com_2 = c * G + s_2 * G'`

`s_0`, `s_1`, and `s_2` MUST be fresh random field elements for every session.
`attr_data` and `c` MUST be canonical field elements. If natural attribute data
is not a single field element, it MUST first be converted into a canonical field
digest as described in Section 11.1.

`com_1` and `com_2` MUST be serialized as canonical Jubjub points. Verifiers
MUST reject malformed commitment points and MUST reject identity commitments
unless the deployment explicitly allows them for a specific field.

### 5.7 Encryption And KDF

Encrypted request and license payloads MUST use authenticated encryption. The
concrete AEAD MAY be supplied by the deployment, but it MUST provide
confidentiality, integrity, nonce misuse resistance appropriate to the chosen
mode, explicit failure on tampering, and unambiguous serialization.

Every encryption key MUST be derived with a domain-separated KDF that includes:

- `deployment_id`;
- message type;
- sender-visible and recipient-visible public context;
- the DH shared point or license key material;
- a salt or nonce value.

The AEAD associated data MUST include all visible fields that identify the
payload context, including at least `deployment_id`, message type, and the
visible stealth address. Implementations MAY use Phoenix AES helpers if they
satisfy these requirements.

AEAD nonces or salts MUST be unique for a given encryption key unless the chosen
AEAD is explicitly nonce-misuse-resistant. Even with a nonce-misuse-resistant
AEAD, implementations SHOULD still keep nonces unique.

Decryption failure MUST be treated as authentication failure. Callers MUST NOT
use unauthenticated plaintext.

### 5.8 Merkle Tree

The license registry is a fixed-parameter Merkle tree over license leaves.

Deployment parameters:

- `MERKLE_ARITY`: tree arity. For this circuit version it MUST be `4`.
- `MERKLE_DEPTH`: tree depth.
- `EMPTY_LEAF`: empty leaf value.
- `ROOT_HISTORY_SIZE`: number of previous roots accepted by the contract, if
  any.

The contract, circuit, wallets, LPs, and SPs MUST use the same tree parameters.
The contract MUST reject license-use proofs whose public `root` is not accepted
under the deployment's root policy.

Accepted roots MUST come from authenticated contract state, not from
user-provided claims.

The license leaf value is `license_hash`. The leaf hash may absorb any
deployment/domain context and license fields required by `license_hash`; this
does not change the Merkle tree arity.

Internal nodes are computed with the fixed Poseidon 4-ary Merkle domain:

`parent = Poseidon[MERKLE4](child_0, child_1, child_2, child_3)`

Child order is part of the Merkle opening. Empty child slots use the deployment
`EMPTY_LEAF` / empty-subtree values.

The recommended root policy is:

- accept the current root;
- optionally accept a bounded history of previous roots to tolerate proving and
  transaction latency.

An SP MAY impose a stricter freshness rule than the contract, for example
requiring the root to be no older than `N` blocks.

## 6. Data Objects

### 6.1 Request

A request asks an LP to issue a license to a user-owned license stealth address.

Fields:

- `deployment_id`
- `rsa`: request stealth address addressed to the LP
- `enc`: AEAD encryption of `lsa || k_lic || request_context`

Where:

- `lsa` is the license stealth address where the license will be issued.
- `k_lic` is license encryption key material derived by the user.
- `request_context` includes `deployment_id`, intended LP key, and any
  LP-required application metadata.

The request ID is:

`request_id = H[CITADEL_REQUEST_ID_V1](rsa, enc)`

LPs MUST maintain a replay policy for request IDs and license stealth
addresses. They MUST NOT issue duplicate licenses for the same `lsa` unless
duplicate issuance is an explicit application requirement.

After decryption, the LP MUST check that `request_context` matches the visible
request fields, intended LP key, `deployment_id`, and deployment profile. A
mismatch invalidates the request.

The protocol does not require requests to be stored by the contract. Requests
MAY be transported through payloads, events, direct LP channels, or application
infrastructure, as long as the cryptographic request format is preserved.

### 6.2 License

A license is an encrypted asset published by an LP.

Fields:

- `deployment_id`
- `lsa` or visible `lpk` coordinates: license stealth address, or the license
  public key coordinates needed to compute the registry leaf
- `enc`: AEAD encryption of `sig_lic || attr_data || license_context`

Where:

- `lpk = lsa.lpk` is the license public key.
- `attr_data` is a canonical scalar or field digest representing the signed
  license attributes.
- `license_context` contains, or is authenticated by, the LP public key or
  `pk_lp.A` signing point, schema ID, issuance metadata, and deployment context
  needed by wallets to verify and interpret the license.
- `sig_lic` is the LP signature over:

  `msg_lic = H[CITADEL_LICENSE_SIG_MSG_V1](lpk.u, lpk.v, attr_data)`

The registry leaf is:

`license_hash = H[CITADEL_LICENSE_HASH_V1](lpk.u, lpk.v)`

The contract MUST derive or verify `license_hash` from visible license public
data, either from `lsa` when the license object is supplied to the contract or
from explicit visible `lpk` coordinates in the issuance argument. It MUST NOT
accept a caller-supplied hash that is inconsistent with the visible license
public key.

Issued license stealth addresses are public registry data. The privacy property
is that a later session proof does not reveal which public license was used.

### 6.3 Session

A session is the public on-chain record created after a successful license-use
proof.

The public input order is fixed:

1. `session_id`
2. `session_hash`
3. `com_0`
4. `com_1.x`
5. `com_1.y`
6. `com_2.x`
7. `com_2.y`
8. `root`

The contract stores the whole public input vector and keys the session by
`session_id`. All implementations MUST preserve this order for this circuit
version.

The public input vector does not carry `deployment_id` as a public input. It is
a deployment constant used to derive the compact context scalars for the
circuit's domain-separated hashes. A session record MUST be interpreted only
together with the deployment metadata under which its proof was verified.

### 6.4 Base Session Cookie

The base disclosure cookie sent by the user to the SP contains:

- `deployment_id`
- `pk_sp`
- `r_session`
- `session_id`
- `pk_lp`
- `attr_data`
- `c`
- `s_0`
- `s_1`
- `s_2`

Here `pk_sp` and `pk_lp` are full Phoenix public keys. The base protocol binds
the session to `pk_sp.A` and commits to `pk_lp.A`.

The cookie reveals the openings needed by the SP. In the base mode, `attr_data`
is disclosed to the SP.

The base session cookie is a bearer credential. Anyone who obtains it can
attempt to replay it to the SP. SPs MUST treat cookies as sensitive credentials
and MUST define a replay policy before using Citadel for real service access.

The cookie or the surrounding authenticated request MUST identify the SP policy
profile being used. The SP MUST NOT infer a policy profile from fields that
could be valid under multiple profiles.

### 6.5 Selective-Disclosure Cookie

In selective-disclosure mode, the user does not reveal the `com_1` opening
directly. The cookie contains the same fields as the base cookie except
`attr_data` and `s_1` MAY be omitted or replaced by disclosed attributes and an
off-chain predicate proof, depending on the SP profile.

The SP profile MUST define the public inputs and statement of the
selective-disclosure proof.

Selective-disclosure cookies and proofs MUST be bound to `session_id`,
`deployment_id`, policy ID, and the SP challenge or nonce when the profile uses
one.

## 7. Issuance And Registry Policy

The license registry has finite capacity. Each deployment MUST define who may
insert license leaves and how spam is controlled.

Acceptable issuance policies include:

- allow-listed LP callers;
- permissionless insertion with fees high enough to price storage and proof
  costs;
- staking or rate-limited issuer registration;
- application-specific governance.

The contract MUST define behavior when the tree is full. It MUST NOT silently
overwrite existing leaves. A deployment MAY rotate to a new tree or contract,
but the migration and accepted-root policy MUST be explicit.

The contract or deployment profile MUST define duplicate `license_hash`
handling. Duplicate leaves SHOULD be rejected unless renewal, migration, or
another application rule explicitly requires them. If duplicates are allowed,
they do not create independent nullification capacity because `session_id`
depends on the hidden license key and challenge, not on the leaf position.

SP trust in LPs is separate from contract insertion permission. A license leaf
being present in the registry proves registration, not that every SP trusts the
issuer.

## 8. Protocol Flow

### 8.1 User Requests A License

The user creates a license destination and sends an encrypted request to the LP.

1. Generate a fresh license stealth address for the user:

   - sample `r_lic <- F`;
   - compute `R_lic = r_lic * G`;
   - compute `k_user = r_lic * pk_user.A`;
   - compute `lpk = H_SCALAR[CITADEL_STEALTH_DERIVE_V1](k_user) * G + pk_user.B`;
   - set `lsa = (lpk, R_lic)`.

2. Derive the license secret key:

   `lsk = H_SCALAR[CITADEL_STEALTH_DERIVE_V1](sk_user.a * R_lic) + sk_user.b`

   The user MUST keep `lsk` secret.

3. Derive license encryption key material:

   `k_lic = KDF[CITADEL_LICENSE_KEY_V1](lsk, lsa)`

4. Generate a fresh request stealth address for the LP:

   - sample `r_req <- F`;
   - compute `R_req = r_req * G`;
   - compute `k_req_point = r_req * pk_lp.A`;
   - compute `rpk = H_SCALAR[CITADEL_STEALTH_DERIVE_V1](k_req_point) * G + pk_lp.B`;
   - set `rsa = (rpk, R_req)`.

5. Derive a request encryption key:

   `k_req = KDF[CITADEL_REQUEST_KEY_V1](k_req_point, rsa, pk_lp)`

6. Encrypt `lsa || k_lic || request_context` with AEAD under `k_req`.

7. Publish or send `Request { deployment_id, rsa, enc }`.

The request transport is deployment-specific. If the request is public, it MUST
not reveal the user's static key or license attributes.

### 8.2 LP Processes A Request

The LP scans request payloads or receives requests through an application
channel.

For each candidate request:

1. Validate all encodings.
2. Compute `k_req_point = sk_lp.a * R_req`.
3. Check ownership of the request stealth address:

   `rpk == H_SCALAR[CITADEL_STEALTH_DERIVE_V1](k_req_point) * G + pk_lp.B`

4. Derive `k_req` with `CITADEL_REQUEST_KEY_V1`.
5. Attempt AEAD decryption. Failure means the request is not accepted.
6. Recover `lsa`, `k_lic`, and request context.
7. Check the request replay policy.
8. Evaluate any off-chain identity, payment, KYC, authorization, or business
   requirements.

The recovered `lsa` tells the LP where to issue the license. It does not reveal
the user's static public key in the request path.

### 8.3 LP Issues A License

If the request is accepted, the LP creates a license.

1. Define the attribute schema and canonical attributes.
2. Compute `attr_data` as specified by the schema. See Section 11.1.
3. Compute:

   `msg_lic = H[CITADEL_LICENSE_SIG_MSG_V1](lpk.u, lpk.v, attr_data)`

4. Sign `msg_lic` with the LP signing secret:

   `sig_lic = SchnorrSign(sk_lp.a, msg_lic)`

5. Encrypt `sig_lic || attr_data || license_context` under `k_lic` with AEAD.

6. Publish `License { deployment_id, lsa, enc }`.

7. Register the license with the contract:

   - the contract validates the visible license public key data;
   - the contract computes `license_hash`;
   - the contract checks issuance authorization or anti-spam policy;
   - the contract inserts `license_hash` into the next available tree slot;
   - the contract records the new root under its root policy;
   - the contract stores or emits the encrypted license blob according to the
     deployment.

The LP MUST NOT reuse the same license stealth address for independent licenses
unless the application explicitly wants those licenses to be linkable.

### 8.4 Direct Issuance

A deployment MAY support direct issuance to a user's public key instead of a
request. Direct issuance derives the license destination and encryption material
using DHKE with the user's public key.

Direct issuance is a lower-privacy mode. The LP can know the user's static
public key or application identity when issuing the license. Wallets and SPs
SHOULD treat direct-issued licenses differently if issuer-verifier
unlinkability matters.

### 8.5 User Fetches A License

The user scans published licenses.

For each license:

1. Validate encodings.
2. Check whether `lsa` belongs to the user by deriving the stealth secret.
3. Derive the applicable license decryption key.
4. AEAD-decrypt the encrypted payload.
5. Verify the LP signature over `msg_lic` using a trusted `pk_lp.A` signing
   point identified by the license context, publication channel, or deployment
   profile.
6. Check that the decrypted `attr_data` matches the expected schema.
7. Verify that the computed `license_hash` is registered under an accepted root.
8. Record the license position, current accepted root, and Merkle opening.

The user SHOULD keep the newest valid license only if the application profile
defines "newest wins". Otherwise, multiple licenses may be independently valid.

### 8.6 SP Publishes A Policy Profile

Before the user opens a session, the SP MUST define the policy it will enforce.
This profile is application-specific.

At minimum, an SP profile MUST define:

- accepted chain ID and contract ID;
- accepted circuit version and verifier key hash;
- accepted generator set, domain constants, and Merkle parameters, if they are
  not implicit in the verifier key;
- SP public service point `pk_sp.A` or service identifier that cookies must bind
  to;
- accepted LP public keys or `pk_lp.A` signing points;
- accepted attribute schema IDs;
- attribute predicates or exact required values;
- challenge derivation and accepted `c` values;
- whether a cookie is one-time, reusable, account-bound, channel-bound,
  client-key-bound, or SP-nonce-bound;
- root freshness requirements, if stricter than the contract;
- expiration and revocation requirements;
- selective-disclosure proof requirements, if base disclosure is not used.

The SP MAY choose any challenge and authorization policy that fits its service,
but it MUST NOT accept arbitrary user-chosen `c` values if it relies on Citadel
for single-use, rate-limited, epoch-limited, or event-limited access.

Recommended challenge template:

`c = H[CITADEL_POLICY_CHALLENGE_V1](sp_id, service_id, policy_id, epoch_or_event_id, sp_nonce)`

This template is a recommendation, not a universal requirement. The mandatory
requirement is that the SP defines exactly which `c` values it accepts.

### 8.7 User Opens An On-Chain Session

To open a session, the user first performs local computations outside the
circuit:

- `lsk`: license secret key. This value MUST stay outside the circuit and MUST
  NOT be shared with a proof helper.
- `lpk = lsk * G`: license public key, equal to `lsa.lpk`.
- `lpk_p = lsk * G'`: secondary license public key.

The user prepares the remaining private witness values:

- `sig_lic`: LP signature on `msg_lic`.
- `pk_lp`: LP public key.
- `attr_data`: signed attribute scalar or digest.
- `c`: SP policy challenge value.
- `r_session`: fresh session randomness. It MUST NOT be reused with the same
  `pk_sp.A`; reuse can make sessions linkable.
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

The double-key signature authorizes the exact public session tuple. This
prevents a proof helper from reusing a signature to submit a different
challenge, root, or commitment tuple.

The user generates a PlonK proof for the license circuit and submits:

- `proof`
- `public_inputs = [session_id, session_hash, com_0, com_1.x, com_1.y, com_2.x, com_2.y, root]`

### 8.8 Contract Verifies License Use

On `use_license`, the contract MUST:

1. Validate public input length and canonical encodings.
2. Verify the PlonK proof with the deployment verifier key.
3. Check that `root` is accepted under the deployment root policy.
4. Reject if `session_id` already exists.
5. Store the session under `session_id`.

The duplicate-session check is the on-chain nullifier mechanism. It only
prevents duplicate sessions for the same hidden license and the same accepted
challenge value. It does not prevent repeated off-chain use of the same cookie.

The duplicate check and session insertion MUST be atomic with proof acceptance.

The contract MAY enforce additional deployment policy, but it does not need to
know SP identity, LP identity, attributes, or challenge value in the base
protocol.

### 8.9 User Requests Service Off-Chain

The user opens an authenticated and confidential channel to the SP and sends the
base session cookie or the selective-disclosure variant required by the SP
profile.

The channel MUST authenticate the SP endpoint. The cookie MUST NOT be sent over
an unauthenticated or plaintext channel.

### 8.10 SP Verifies The Cookie

The SP fetches the session by `session_id` from authenticated and sufficiently
finalized contract state. It verifies that the session belongs to the expected
deployment, contract, and circuit version.

The fetched session provides the public `session_id`, `session_hash`, `com_0`,
`com_1`, `com_2`, and `root` values that the cookie must open.

For the base disclosure cookie, the SP MUST verify:

1. The session exists.
2. The fetched public input vector has the expected length and canonical
   encodings, and `com_1` and `com_2` decode to valid non-identity Jubjub
   points.
3. The cookie `session_id` equals the fetched session ID.
4. The cookie `deployment_id` matches the SP profile.
5. `pk_sp.A` equals the SP public service point for this profile.
6. `H[CITADEL_SESSION_HASH_V1](pk_sp.A.u, pk_sp.A.v, r_session) == session.session_hash`.
7. `H[CITADEL_LP_COMMITMENT_V1](pk_lp.A.u, pk_lp.A.v, s_0) == session.com_0`.
8. `attr_data * G + s_1 * G' == session.com_1`.
9. `c * G + s_2 * G' == session.com_2`.
10. `pk_lp` or `pk_lp.A`, according to the profile identifier rule, is in the
    SP's accepted issuer set for this policy.
11. `attr_data` satisfies the SP's accepted schema and attribute policy. If
    `attr_data` is a digest, the cookie must disclose the attributes and
    blinding needed to open it, or the user must provide the
    selective-disclosure proof required by the profile.
12. `c` exactly matches the SP's challenge policy.
13. The session root satisfies the SP's freshness policy.
14. Expiration and revocation requirements are satisfied.
15. Cookie replay, account binding, channel binding, and rate-limit checks pass.

Only after all required checks pass MAY the SP grant service.

The SP MUST record cookie or session consumption if service is intended to be
one-time. For reusable service, the SP MUST define the reuse limits explicitly.

## 9. License Circuit

The license circuit proves knowledge of private values satisfying the statements
below.

`deployment_id`, generator choices, domain constants, and Merkle parameters are
fixed deployment constants for this circuit version unless a future circuit
version explicitly makes them public inputs.

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

`lpk` and `lpk_p` are private witness points. The circuit does not compute
`lpk = lsk * G` or `lpk_p = lsk * G'`, and `lsk` is not a circuit witness. The
relation between `lpk`, `lpk_p`, and the user's license secret is proved by the
double-key Schnorr verification.

The circuit enforces:

1. The session ID is correctly derived:

   `session_id = H[CITADEL_SESSION_ID_V1](lpk_p.u, lpk_p.v, c)`

2. The LP signature verifies:

   - message is `msg_lic = H[CITADEL_LICENSE_SIG_MSG_V1](lpk.u, lpk.v, attr_data)`;
   - `sig_lic` verifies under `pk_lp.A`.

3. The user knows the license secret key corresponding to both private witness
   points:

   - `session_auth = H[CITADEL_SESSION_AUTH_V1](session_id, session_hash, com_0, com_1.x, com_1.y, com_2.x, com_2.y, root)`;
   - `sig_session_auth` is a valid double-key Schnorr signature over
     `session_auth`;
   - the public keys used by the double-key verification are `(lpk, lpk_p)`;
   - the double-key statement proves knowledge of the same scalar for `G` and
     `G'`.

4. The LP commitment opens:

   `com_0 = H[CITADEL_LP_COMMITMENT_V1](pk_lp.A.u, pk_lp.A.v, s_0)`

5. The attribute commitment opens:

   `com_1 = attr_data * G + s_1 * G'`

6. The challenge commitment opens:

   `com_2 = c * G + s_2 * G'`

7. The license leaf is in the license Merkle tree:

   - `license_hash = H[CITADEL_LICENSE_HASH_V1](lpk.u, lpk.v)`;
   - the private Merkle path opens `license_hash` under public `root`.

The circuit does not prove that the SP trusts `pk_lp` or `pk_lp.A`, that
attributes satisfy a service policy, that `session_hash` opens to the SP's
configured `pk_sp.A`, that `c` is accepted by the SP, that the cookie was not
replayed, or that a license has not been revoked unless those checks are added
by a deployment-specific extension.

## 10. Challenge And Reuse Semantics

The challenge `c` controls nullification.

For a fixed license secret and a fixed `c`, `session_id` is deterministic. The
contract rejects a second session with the same `session_id`.

If the SP accepts arbitrary `c` values, a user can create many distinct sessions
from the same license. This is not a cryptographic failure; it is an SP policy
failure.

Common profiles:

- Single-use forever: `c` is a fixed constant for the service policy.
- Once per event: `c` is derived from event ID and policy ID.
- Once per epoch: `c` is derived from epoch or date.
- SP-nonce gated: `c` includes a fresh SP nonce and the SP records that nonce or
  session as consumed.
- Account-bound access: `c` or the SP's replay table binds the session to an
  authenticated account or client key.

These are examples. SPs MAY define other profiles, but they MUST be exact and
verifiable.

## 11. Attributes And Disclosure

### 11.1 Attribute Data

`attr_data` is the value signed by the LP and committed in the session.

Every supported attribute schema MUST define:

- schema ID and version;
- canonical serialization;
- byte-to-field or hash-to-field mapping;
- required and optional fields;
- issuer scope;
- service or policy scope, if applicable;
- issuance time, expiration time, or explicit no-expiration marker;
- privacy mode: base disclosure or selective disclosure.

For base disclosure, `attr_data` MAY be a directly encoded scalar if the schema
fits in one field element. More commonly:

`attr_data = H[CITADEL_ATTR_DATA_V1](schema_id, canonical_attributes, r_attr)`

where `r_attr` is fresh attribute blinding randomness known to the user and LP.

If `attr_data` is a digest, the SP cannot infer its semantics from the base
cookie unless the user also discloses the attributes and `r_attr`, or provides a
selective-disclosure proof.

Because the LP knows the `attr_data` it signed, base disclosure of `attr_data`
can be a stable correlation handle if the LP and SP collude. A profile that
needs issuer-verifier unlinkability SHOULD use selective disclosure or another
profile that does not reveal an LP-known value to the SP.

Attributes SHOULD include expiration or validity information unless the license
is intentionally permanent.

### 11.2 Selective Disclosure

Base disclosure reveals `attr_data` or the data needed to interpret it to the
SP. For privacy-sensitive services, an SP SHOULD use a selective-disclosure
profile.

A selective-disclosure profile defines an off-chain proof with public inputs
such as:

- `com_1` from the on-chain session;
- `session_id`;
- `deployment_id`;
- schema ID;
- policy ID;
- disclosed attributes, if any;
- SP challenge or nonce, if needed.

The private witnesses include:

- hidden attributes;
- `r_attr`;
- `attr_data`;
- `s_1`.

The proof MUST show:

1. `attr_data = H[CITADEL_ATTR_DATA_V1](schema_id, canonical_attributes, r_attr)`.
2. `com_1 = attr_data * G + s_1 * G'`.
3. The attributes satisfy the SP's predicate.
4. Any disclosed attributes are consistent with the hidden committed attributes.
5. The proof is bound to the intended session, deployment, policy profile, and
   SP challenge or nonce.

LPs and SPs MUST agree on the schema and predicate circuit. A generic Citadel
session verifier cannot infer selective-disclosure semantics without that
profile.

## 12. Revocation, Expiration, And Replay

### 12.1 Revocation And Current Validity

The base registry is append-only membership. It proves that a license was
registered under an accepted root. It does not prove that the license is still
valid unless the deployment or SP profile adds such a rule.

Deployments and SPs MUST NOT claim revocation support unless they implement one
of the following:

- signed expiration or validity interval in `attr_data`, enforced by the SP;
- SP-maintained deny list keyed by session, account, disclosed credential, or
  other application identifier;
- contract-maintained revocation or status accumulator with a circuit proof of
  non-revocation;
- epoch-specific roots with strict root freshness and migration rules.

If revocation is security-critical, an SP-side deny list alone may be
insufficient because base sessions hide the license key. The deployment SHOULD
use a protocol-level status mechanism or attributes that reveal only the minimum
identifier needed for revocation under the service's privacy model.

Old accepted roots can bypass revocation if the revocation design is not bound
to root freshness. Root age and status checks MUST be designed together.

If expiration or revocation status is hidden inside an attribute digest and is
neither disclosed nor proven in a selective-disclosure proof, the SP has not
enforced expiration or revocation.

### 12.2 Cookie Replay And Binding

A base session cookie is a bearer credential. The on-chain nullifier prevents
duplicate session creation, not duplicate service use.

Each SP profile MUST define at least one of:

- one-time cookie use, with server-side consumption state;
- reusable cookie use, with explicit limits;
- channel-bound cookie use;
- account-bound cookie use;
- client-key-bound cookie use;
- SP-nonce-bound cookie use.

Recommended one-time profile:

1. SP issues a fresh nonce and policy ID.
2. User derives `c` from `deployment_id`, SP ID, service ID, policy ID, and
   nonce.
3. User opens a session and sends the cookie.
4. SP verifies the cookie and atomically marks the nonce or `session_id`
   consumed.
5. Future use of the same nonce or `session_id` is rejected.

For long-lived sessions, the SP SHOULD bind access to an authenticated account
or client-held key and set a clear expiration.

## 13. Privacy Properties And Limits

### 13.1 On-Chain Observers

On-chain observers see:

- encrypted license blobs, if published on-chain;
- license stealth addresses;
- license hashes;
- Merkle roots;
- session public inputs;
- transaction timing and fees.

They should not learn:

- which license was used in a session;
- the user wallet public key;
- the LP public key used in the proof;
- the SP public key used in the session;
- signed attributes;
- challenge value;
- Merkle path.

These privacy properties rely on fresh randomness, valid commitments, PlonK zero
knowledge, and users not reusing stealth secrets.

### 13.2 LP And SP Knowledge

The LP learns whatever the user discloses during license request review and the
attributes it signs. In request-based issuance, the LP does not learn the user's
static public key from the cryptographic request alone.

The SP learns whatever is disclosed by the selected cookie mode and policy
proof. In base mode, it learns `attr_data` or enough data to interpret it.

If the LP also knows that same `attr_data`, the value itself can link issuance
and service use under LP/SP collusion.

If the LP and SP collude, unique attributes, request metadata, timing, payments,
network metadata, or direct issuance can link issuance to service use. Citadel
does not prevent correlation through non-cryptographic side channels.

### 13.3 Proof Helpers

A user MAY delegate proof generation to a proof helper without revealing `lsk`.
The helper MUST NOT receive `lsk`; the user computes `sig_session_auth` locally
and sends the helper only the resulting signature and the other proving inputs
needed by the circuit.

The helper may still learn sensitive metadata, including which license leaf and
LP are involved, unless additional blinding or local proving is used.

Proof-helper delegation is an operational choice and must be evaluated under
the user's privacy requirements.

## 14. Security Assumptions

Citadel relies on:

- discrete-log hardness on Jubjub;
- binding and hiding properties of Pedersen commitments with independent
  generators;
- collision resistance and circuit-appropriate security of Poseidon with proper
  domain separation;
- Schnorr signature unforgeability in the relevant random-oracle model;
- PlonK soundness and zero-knowledge for the deployed circuit and verifier key;
- correct PlonK setup or verifier-key generation according to the deployment's
  proof-system assumptions;
- AEAD confidentiality and integrity;
- correct DHKE and KDF use;
- fresh randomness;
- canonical encoding and point validation;
- contract root anchoring;
- authenticated and sufficiently finalized contract-state reads by wallets and
  SPs;
- SP enforcement of issuer, attribute, challenge, replay, revocation, and
  service policy.

If any of these assumptions does not hold, the affected security property does
not hold.

## 15. Conformance Checklist

A deployment conforms to this specification only if:

- every Poseidon, KDF, and signature context is domain-separated;
- every external point and scalar is canonically validated;
- request and license encryption is authenticated and context-bound;
- license hashes are derived from visible license public key data;
- issuance access and tree-capacity behavior are explicit;
- duplicate `license_hash` handling is explicit;
- Merkle roots in license-use proofs are checked against contract-accepted
  roots;
- wallets and SPs use authenticated contract state with the deployment's
  finality policy;
- public input order is fixed and versioned;
- the double-key session authorization signature binds the exact public input
  tuple;
- duplicate `session_id` values are rejected atomically;
- SP profiles define exact challenge validation;
- SPs verify that `pk_sp.A` in a cookie is their configured service point for
  the selected policy;
- SPs treat cookies as bearer credentials unless they add binding;
- selective-disclosure proofs are bound to the intended session, deployment,
  policy, and SP challenge or nonce;
- expiration and revocation are not claimed unless implemented by the profile;
- attribute schemas are canonical and versioned;
- direct issuance is marked as a lower-privacy mode.

## 16. Minimal Safe Deployment Guidance

For an academic or prototype deployment:

- use request-based issuance;
- allow-list LP issuers or require fees for registry insertion;
- keep a bounded root history;
- use base disclosure only for non-sensitive attributes;
- use fixed or policy-derived challenges bound to deployment, SP, service, and
  policy context, never arbitrary user challenges;
- treat cookies as one-time unless the service is explicitly reusable;
- include expiration in attributes;
- document that protocol-level revocation is not available unless a status
  extension is deployed.

For production deployments, Citadel should undergo implementation review,
circuit review, verifier-key review, dependency review, and operational security
review in addition to this protocol specification.
