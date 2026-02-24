# Proposal: Remote Credential Signing for Kubernetes Environments

## Table of Contents

- [1. Problem Statement](#1-problem-statement)
- [2. Goals and Non-Goals](#2-goals-and-non-goals)
- [3. Current Architecture Recap](#3-current-architecture-recap)
- [4. Proposed Architecture](#4-proposed-architecture)
- [5. Detailed Flow](#5-detailed-flow)
- [6. Remote Signing Service (CredSigner)](#6-remote-signing-service-credsigner)
- [7. Agent Changes](#7-agent-changes)
- [8. Server Changes](#8-server-changes)
- [9. Protocol Changes](#9-protocol-changes)

---

## 1. Problem Statement

DAOS authentication relies on the `daos_agent` having access to a **private RSA key**
(`/etc/daos/certs/agent.key`) to sign credentials. The corresponding public
certificate (`agent.crt`) is deployed to every DAOS server node for verification.
The agent determines client identity via the `SO_PEERCRED` kernel mechanism on a
Unix domain socket - it reads the connecting process's UID/GID, resolves them to
usernames, and signs the result.

This model is designed for bare-metal HPC clusters where:
- A node-wide agent daemon is a trusted, privileged service with access to secrets
  that client processes cannot read.
- Clients are processes with meaningful Unix UIDs that map to real users via
  `/etc/passwd` or NSS.

**In Kubernetes, both assumptions break down:**

- **No node-wide privileged agent.** There is no established pattern for running a
  per-node DaemonSet that holds secrets inaccessible to application pods. Kubernetes
  secrets are either mounted into pods (accessible to the app) or stored externally.

- **`SO_PEERCRED` UIDs are meaningless in containers.** Inside a container, the UID
  may be `root` (0), a hardcoded non-root UID like 1000, or arbitrary - it reflects
  the container's user namespace, not an organization's user directory. There is no
  reliable mapping from container UID to a meaningful DAOS principal like `alice@`.

In Kubernetes, workload identity is best established by the platform, not by Unix
UIDs. We propose running the agent as a **sidecar container** within each application
pod, where:

1. The **JWT from the company's IdentityServer** is the sole source of user identity
   (replacing `SO_PEERCRED` + local user lookup).
2. A **remote CredSigner service** holds the signing key and produces DAOS credentials
   (replacing local RSA signing with `agent.key`).

The agent becomes a lightweight proxy: it obtains a JWT asserting the pod's user
identity, forwards it to the CredSigner, and returns the signed DAOS credential to
`libdaos`.

---

## 2. Goals and Non-Goals

### Goals

1. **Eliminate private keys and certificates on Kubernetes worker nodes.** The agent
   sidecar does not need access to any RSA private key or X.509 certificate for
   credential signing.

2. **Eliminate `SO_PEERCRED` dependency in Kubernetes.** User identity comes from
   a JWT issued by the company's IdentityServer, not from container UIDs.

3. **Leverage existing identity infrastructure.** The agent obtains a user JWT
   from the company's IdentityServer (in a company-specific way), integrating with
   the platform's existing OIDC/JWT-based identity.

4. **Preserve the DAOS security model on the server side.** The credential format
   (`AUTH_SYS` token + verifier), server-side validation, ACL matching, and
   capability caching are unchanged. DAOS servers see the same `Credential` protobuf
   they see today.

### Non-Goals

- **Changing the auth flavor.** This proposal uses `AUTH_SYS` - the token format and
  server-side validation are unchanged. This is not a new auth flavor like `AUTH_KRB5`.

---

## 3. Current Architecture Recap

For reference, the current `AUTH_SYS` credential flow (see
[authentication.md](authentication.md) for full details):

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        CURRENT: Local Signing                           │
└─────────────────────────────────────────────────────────────────────────┘

  Client App              Agent (daemon)                    DAOS Server
  (libdaos)               has agent.key                     has agent.crt
      │                        │                                │
      │ 1. dRPC: RequestCreds  │                                │
      │───────────────────────>│                                │
      │   (Unix socket)        │                                │
      │                        │ 2. SO_PEERCRED → uid/gid       │
      │                        │ 3. Lookup user → "alice@"      │
      │                        │ 4. Build AUTH_SYS token        │
      │                        │ 5. Sign with agent.key (RSA)   │
      │                        │                                │
      │ 6. Credential          │                                │
      │   {token, verifier,    │                                │
      │    origin="agent"}     │                                │
      │<───────────────────────│                                │
      │                                                         │
      │ 7. pool_connect RPC (credential attached)               │
      │────────────────────────────────────────────────────────>│
      │                                                         │
      │                              8. Load agent.crt          │
      │                              9. Verify RSA-PSS sig      │
      │                             10. Extract principal       │
      │                             11. Check ACL, cache capas  │
      │                                                         │
      │ 12. Handle UUID                                         │
      │<────────────────────────────────────────────────────────│
```

**What breaks in Kubernetes:**
- Step 2: `SO_PEERCRED` returns a container UID (e.g., 0 or 1000) with no meaningful
  mapping to a DAOS user.
- Step 3: Local `/etc/passwd` inside the container doesn't contain real users.
- Step 5: Requires `agent.key` on the node - difficult to protect in K8s.

---

## 4. Proposed Architecture

The agent runs as a **sidecar container** within each application pod. It has no
private keys. User identity is established by a **JWT** from the company's
IdentityServer, and credential signing is delegated to a centralized **CredSigner**
service.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      PROPOSED: Sidecar + Remote Signing                     │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌─ Application Pod ────────────────────┐
  │                                      │ IdentityServer  CredSigner      DAOS Server
  │  App Container     Agent Sidecar     │ (company OIDC)  (has agent.key) (has agent.crt)
  │  (libdaos)         (no keys)         │      │               │               │
  │      │                  │            │      │               │               │
  │      │ 1. dRPC          │            │      │               │               │
  │      │─────────────────>│            │      │               │               │
  │      │  (Unix socket    │            │      │               │               │
  │      │   shared via     │            │      │               │               │
  │      │   emptyDir vol)  │            │      │               │               │
  │      │                  │            │      │               │               │
  │      │            2. Request JWT     │      │               │               │
  │      │                  │────────────┼─────>│               │               │
  │      │                  │            │      │               │               │
  │      │                  │            │      │ Validate K8s  │               │
  │      │                  │            │      │ SA token, map │               │
  │      │                  │            │      │ pod → user    │               │
  │      │                  │            │      │               │               │
  │      │                  │<───────────┼──────│               │               │
  │      │                  │ JWT        │      │               │               │
  │      │                  │ sub="alice"│      │               │               │
  │      │                  │ groups=    │      │               │               │
  │      │                  │  ["users", │      │               │               │
  │      │                  │   "devs"]  │      │               │               │
  │      │                  │            │      │               │               │
  │      │            3. Request signed credential              │               │
  │      │                  │────────────┼──────┼──────────────>│               │
  │      │                  │  {jwt}     │      │               │               │
  │      │                  │            │      │  4. Validate JWT              │
  │      │                  │            │      │  5. Extract identity          │
  │      │                  │            │      │     from JWT claims           │
  │      │                  │            │      │  6. Build AUTH_SYS token      │
  │      │                  │            │      │  7. Sign with agent.key       │
  │      │                  │            │      │  8. Return Credential         │
  │      │                  │            │      │               │               │
  │      │                  │<───────────┼──────┼───────────────│               │
  │      │                  │ Credential │      │               │               │
  │      │                  │            │      │               │               │
  │      │ 9. Credential    │            │      │               │               │
  │      │<─────────────────│            │      │               │               │
  │      │                  │            │      │               │               │
  └──────┼──────────────────┼────────────┘      │               │               │
         │                                                                      │
         │ 10. pool_connect RPC (same credential format as today)               │
         │─────────────────────────────────────────────────────────────────────>│
         │                                                                      │
         │                                        11. Load agent.crt            │
         │                                        12. Verify RSA-PSS sig        │
         │                                        13. Check ACL, cache capas    │
         │                                                                      │
         │ 14. Handle UUID                                                      │
         │<─────────────────────────────────────────────────────────────────────│
```

### Key Design Decisions

1. **Sidecar, not DaemonSet.** The agent runs as a sidecar in each application pod.
   This avoids the node-wide secret problem entirely. The agent and the app share a
   Unix socket via an `emptyDir` volume, so `libdaos` connects to the agent exactly
   as it does today.

2. **JWT is the sole identity source.** The agent does NOT use `SO_PEERCRED`. There is
   no local UID → username lookup. The user's identity (principal, groups) comes
   entirely from the JWT claims issued by the IdentityServer.

3. **CredSigner extracts identity from JWT.** The CredSigner validates the JWT and
   uses its claims (`sub`, `groups`, etc.) to build the `AUTH_SYS` token. The agent
   does not need to send user/group information separately - the JWT is the single
   source of truth.

4. **Server side is unchanged.** Steps 10-14 are identical to today. The DAOS server
   sees the same `Credential` protobuf.

---

## 5. Detailed Flow

### Step 1: Client Requests Credentials

Unchanged from `libdaos`'s perspective. The client connects to the agent via Unix
domain socket and calls `dc_sec_request_creds()`.

The difference is deployment: the Unix socket is shared between the app container and
the agent sidecar via a Kubernetes `emptyDir` volume, rather than being a node-wide
socket provided by a DaemonSet.

```yaml
# Pod spec excerpt
volumes:
  - name: daos-agent-socket
    emptyDir: {}
containers:
  - name: app
    volumeMounts:
      - name: daos-agent-socket
        mountPath: /var/run/daos_agent
  - name: daos-agent
    volumeMounts:
      - name: daos-agent-socket
        mountPath: /var/run/daos_agent
```

### Step 2: Agent Obtains JWT from IdentityServer

This replaces the `SO_PEERCRED` + local user lookup steps in the current flow.
The agent requests a JWT from the company's IdentityServer that asserts the pod's
user identity.

```
Agent Sidecar                  IdentityServer
  │                                  │
  │  POST /token                     │
  │  Authorization: Bearer <K8s SA>  │
  │  {                               │
  │    "grant_type": "...",          │
  │    "audience": "daos-credsigner" │
  │  }                               │
  │─────────────────────────────────>│
  │                                  │
  │  The IdentityServer:             │
  │  - Determines the user identity  │
  │    associated with this pod      │
  │  - Issues a short-lived JWT      │
  │    with user identity claims     │
  │                                  │
  │  200 OK                          │
  │  {                               │
  │    "token": "eyJhbGci..."        │
  │  }                               │
  │<─────────────────────────────────│
  │                                  │
```

The JWT is short-lived (e.g., 5 minutes) and scoped to the `daos-credsigner`
audience.

### Step 3: Agent Sends JWT to CredSigner

The agent forwards the JWT to the CredSigner. Since the JWT contains all necessary
identity information, the request is simple - just the JWT itself plus optional
metadata.

```
Agent Sidecar                  CredSigner
  │                                  │
  │  gRPC: SignCredential            │
  │  {                               │
  │    jwt: "eyJhbGci...",           │
  │    machinename: "train-7f8b9"    │
  │  }                               │
  │─────────────────────────────────>│
  │                                  │
```

The `machinename` is the only field the agent provides beyond the JWT - it identifies
the originating pod/host for the `Sys.machinename` field in the DAOS credential.
All user identity (principal, groups) comes from the JWT claims.

### Steps 4-8: CredSigner Validates and Signs

The CredSigner:

1. **Validates the JWT** - checks signature (against IdentityServer's JWKS), expiry,
   audience (`daos-credsigner`), and issuer.

2. **Extracts identity from JWT claims** - the CredSigner reads the user principal
   and groups directly from the JWT.

3. **Builds the `AUTH_SYS` token** - exactly the same `Sys` protobuf that the agent
   builds today:

   ```go
   sys := auth.Sys{
       Stamp:       0,
       Machinename: req.Machinename,    // "train-7f8b9"
       User:        claims.Principal,    // "alice@" (from JWT)
       Group:       claims.Group,        // "users@" (from JWT)
       Groups:      claims.Groups,       // ["users@", "devs@"] (from JWT)
       Secctx:      "",
   }
   ```

4. **Signs the token** - using the same RSA-PSS signing that the agent does today,
   with the private key that only the CredSigner has:

   ```go
   token := auth.Token{Flavor: auth.Flavor_AUTH_SYS, Data: tokenBytes}
   verifier, _ := auth.VerifierFromToken(signingKey, &token)
   ```

5. **Returns the `Credential`** - the same protobuf the agent would have built
   locally:

   ```go
   credential := auth.Credential{
       Token:    &token,
       Verifier: &verifierToken,
       Origin:   "agent",  // same origin - server uses this to find agent.crt
   }
   ```

### Step 9: Agent Returns Credential to Client

The agent passes through the `Credential` from the CredSigner to the client, wrapped
in `GetCredResp`. From `libdaos`'s perspective, nothing is different.

### Steps 10-14: Server Validates (UNCHANGED)

The DAOS server receives the credential and validates it exactly as it does today:

1. `daos_engine` sends the credential to `daos_server` via dRPC
2. `daos_server` loads `agent.crt` from `ClientCertDir`
3. `daos_server` verifies the RSA-PSS signature
4. `daos_engine` extracts the `AUTH_SYS` payload, checks ACLs, caches capabilities

---

## 6. Remote Signing Service (CredSigner)

he CredSigner is a new, standalone service whose sole job is to accept a JWT,
validate it, extract user identity from its claims, and return a signed DAOS
`Credential`. It holds the `agent.key` private key and performs the same RSA-PSS
signing that the agent does today - the difference is that identity comes from a JWT
instead of `SO_PEERCRED`. It returns the existing `security.auth.Credential` protobuf
from `src/proto/security/auth.proto` - no new credential types are introduced.

### Implementation details

***TBD***

## 7. Agent Changes

### Overview

The agent sidecar is a significantly simplified variant of the current agent. In
remote mode, it does not use `SO_PEERCRED`, does not look up local users, and does
not hold any signing keys. Its only jobs are:

1. Listen on the Unix socket for `libdaos` dRPC requests
2. Obtain a JWT from the IdentityServer
3. Forward the JWT to the CredSigner
4. Return the signed credential

## 8. Server Changes

### None

This is the key advantage of the design. The DAOS server (`daos_server` and
`daos_engine`) requires **zero modifications**:

- The `Credential` protobuf is identical - same `AUTH_SYS` flavor, same token
  structure, same RSA-PSS verifier.
- `processValidateCredentials()` in `src/control/server/security_rpc.go` works
  unchanged.
- `get_auth_sys_payload()` in `src/security/srv_acl.c` works unchanged.
- ACL matching in `src/security/acl.c` works unchanged.

The server does not know - and does not need to know - whether the credential was
signed locally by the agent or remotely by the CredSigner, or whether identity was
determined via `SO_PEERCRED` or JWT. The cryptographic verification is the same
either way: RSA-PSS signature verified against the public key in `agent.crt`.

---

## 9. Protocol Changes

### DAOS Protobuf (`src/proto/security/auth.proto`)

**No changes.** The `Credential`, `Token`, `Sys`, and `Flavor` messages are
unchanged. Remote signing produces the same byte-for-byte protobuf that local signing
produces.

