# DAOS Authentication & Security System

This document describes how authentication and authorization work in DAOS, based on code analysis.

> **Note:** This document was co-authored with Claude Code (AI assistant). While information has been cross-referenced with source code, readers should verify critical details independently.

## Table of Contents

- [Overview](#overview)
- [Key Architecture Principles](#key-architecture-principles)
- [Authentication Flow](#authentication-flow)
- [Token Structure](#token-structure)
- [Server-Side Validation](#server-side-validation)
- [Capability-Based Authorization](#capability-based-authorization)
- [ACL Matching](#acl-matching)
- [ClientUserMap](#clientusermap)
- [Performance Analysis](#performance-analysis)
- [Security Properties](#security-properties)
- [Important Code Locations](#important-code-locations)

## Overview

DAOS uses a **two-phase authentication model**:
1. **Connection time**: Validate credentials, compute capabilities, store in handle
2. **Subsequent operations**: Check cached capabilities (no re-validation)

This design achieves both security and high performance for I/O operations.

## Key Architecture Principles

1. **Client is untrusted** - `libdaos` can be tampered with or replaced
2. **Agent is trusted** - Signs credentials using certificates
3. **Validate once, cache capabilities** - Performance optimization
4. **Server-side sessions** - Handles stored on server, client cannot tamper
5. **Textual principals** - Tokens contain usernames (e.g., "alice@"), not UIDs

## Authentication Flow

### 1. Client Requests Credentials from Agent

**Location**: `src/security/cli_security.c`

```c
int dc_sec_request_creds(d_iov_t *creds)
{
    // Connect to agent via Unix Domain Socket
    drpc_connect(dc_agent_sockpath, &agent_socket);

    // Request credentials (no payload needed - identity from socket)
    drpc_call(agent_socket, DRPC_MODULE_SEC_AGENT,
              DRPC_METHOD_SEC_AGENT_REQUEST_CREDS, &response);

    // Returns packed Auth__Credential
    return get_cred_from_response(response, creds);
}
```

### 2. Agent Creates Signed Credential

**Location**: `src/control/cmd/daos_agent/security_rpc.go`

```go
func (m *SecurityModule) getCredential(ctx context.Context, session *drpc.Session) ([]byte, error) {
    // 1. Extract REAL UID/GID from Unix socket (kernel-verified!)
    info, err := security.DomainInfoFromUnixConn(m.log, uConn)
    // Uses SO_PEERCRED socket option - client cannot fake this

    // 2. Lookup username from UID
    // Normal: user.LookupId("1000") → "alice"
    // Fallback: ClientUserMap.Lookup(1000) → mapped user

    // 3. Create AUTH_SYS token
    sys := Sys{
        Machinename: hostname,
        User:        "alice@",              // String, not UID!
        Group:       "users@",              // String, not GID!
        Groups:      ["users@", "devs@"],   // All groups
        Secctx:      selinux_context,
    }

    // 4. Sign token with agent's private key
    verifier := SignWithPrivateKey(agent_key, token)
    // In secure mode: RSA/ECDSA signature
    // In insecure mode: SHA512 hash

    // 5. Return credential
    return &Credential{
        Token:    &token,
        Verifier: &verifier,
        Origin:   "agent",
    }
}
```

**Critical**: The UID/GID comes from the kernel via `SO_PEERCRED` socket option - the client process cannot forge these values.

### 3. Server Validates Credential (ONE TIME)

**Location**: `src/security/srv_acl.c`

```c
int ds_sec_pool_get_capabilities(uint64_t flags, d_iov_t *cred,
                                 struct d_ownership *ownership,
                                 struct daos_acl *acl, uint64_t *capas)
{
    Auth__Token *token;

    // 1. Validate credential via dRPC to control plane
    rc = ds_sec_validate_credentials(cred, &token);
    // Control plane verifies signature with agent's public key

    // 2. Extract user identity from token
    Auth__Sys *authsys;
    rc = get_auth_sys_payload(token, &authsys);
    // authsys->user = "alice@"
    // authsys->groups = ["users@", "developers@"]

    // 3. Build user_info structure
    struct acl_user user_info = {
        .user = authsys->user,
        .groups = authsys->groups,
        .nr_groups = authsys->n_groups,
    };

    // 4. Check ACL permissions
    rc = get_acl_permissions(acl, ownership, &user_info,
                             owner_min_perms, &perms, &is_owner);
    // Matches user/groups against ACL entries

    // 5. Convert permissions to capabilities
    *capas = pool_capas_from_perms(perms, is_owner);
    // PERM_READ → POOL_CAPA_READ
    // PERM_WRITE → POOL_CAPA_CREATE_CONT | POOL_CAPA_DEL_CONT

    // 6. Filter by requested flags
    filter_pool_capas_based_on_flags(flags, capas);

    return 0;
}
```

**Control plane signature verification** (`src/control/server/security_rpc.go`):

```go
func (m *SecurityModule) processValidateCredentials(body []byte) ([]byte, error) {
    req := &auth.ValidateCredReq{}
    proto.Unmarshal(body, req)

    cred := req.Cred

    // Load agent's public certificate
    certPath := filepath.Join(m.config.ClientCertDir, "agent.crt")
    cert, err := security.LoadCertificate(certPath)
    key := cert.PublicKey

    // Verify signature
    err = auth.VerifyToken(key, cred.GetToken(), cred.GetVerifier().GetData())
    // RSA/ECDSA signature verification using public key

    // Return validated token
    return &auth.ValidateCredResp{Token: cred.Token}
}
```

### 4. Server Creates Handle with Cached Capabilities

**Location**: `src/include/daos_srv/pool.h`

```c
struct ds_pool_hdl {
    d_list_t        sph_entry;
    uuid_t          sph_uuid;        // Handle UUID (unguessable)
    uint64_t        sph_flags;       // User flags (RO/RW/EX)
    uint64_t        sph_sec_capas;   // ← CACHED CAPABILITIES
    struct ds_pool *sph_pool;
    d_iov_t         sph_cred;        // Original credential (for reference)
};

// Stored in global hash table
pool_hdl_hash[handle_uuid] = pool_hdl;
```

The handle UUID is returned to the client and used for all subsequent operations.

## Token Structure

**Definition**: `src/proto/security/auth.proto`

```protobuf
// AUTH_SYS token contains TEXTUAL principals, not numerical IDs
message Sys {
    uint64 stamp = 1;              // timestamp
    string machinename = 2;        // "node123"
    string user = 3;               // "alice@"  ← String, not UID!
    string group = 4;              // "users@"  ← String, not GID!
    repeated string groups = 5;    // ["users@", "developers@"]
    string secctx = 6;             // SELinux context
}

message Token {
    Flavor flavor = 1;  // AUTH_SYS
    bytes data = 2;     // Packed Sys struct
}

message Credential {
    Token token = 1;     // User identity
    Token verifier = 2;  // Signature (secure) or hash (insecure)
    string origin = 3;   // "agent"
}
```

**Key insight**: The token contains textual principals for ACL matching, not numerical UIDs/GIDs. This provides better cross-system compatibility and aligns with ACL entries.

## Server-Side Validation

Validation happens via **dRPC** (Unix Domain Socket) communication:

```
Data Plane (C)              Control Plane (Go)
daos_engine                 daos_server
     │                           │
     │  ValidateCredentials      │
     │  (via dRPC)               │
     ├──────────────────────────>│
     │                           │
     │                    1. Load agent cert
     │                    2. Extract public key
     │                    3. Verify signature
     │                           │
     │  Validated Token          │
     │<──────────────────────────┤
     │                           │
```

The control plane has access to agent certificates (`/etc/daos/certs/clients/agent.crt`) and performs cryptographic verification.

## Capability-Based Authorization

After initial validation, subsequent operations check **cached capabilities** without re-validating credentials.

## libdfs Authentication

**Location**: `src/client/dfs/`

libdfs (DAOS File System library) uses the **same authentication flow** as any other libdaos client. There is no special authentication for filesystem operations.

### Authentication Sequence

When an application uses libdfs to mount a DAOS container as a filesystem, authentication happens in three steps:

#### Step 1: Pool Connection (Authentication Happens Here)

```c
// Connect to pool - this triggers the full authentication flow
daos_handle_t poh;
int rc = daos_pool_connect(pool_uuid, NULL, DAOS_PC_RW, &poh, NULL, NULL);
```

**What happens** (`src/pool/cli.c:dc_pool_connect_internal`):

1. **Request credential from agent** (`src/security/cli_security.c`):
   ```c
   d_iov_t *credp;
   pool_connect_in_get_cred(rpc, &credp);
   rc = dc_sec_request_creds(credp);  // Connects to agent via dRPC
   ```

2. **Agent signs credential** (`src/control/security/auth/auth_sys.go`):
   - Extracts process UID/GID via `SO_PEERCRED` from Unix socket
   - Creates `Auth__Sys` token with user info
   - Signs token with agent's RSA private key (secure mode)
   - Returns signed credential to libdaos

3. **Send pool connect RPC to server** with signed credential

4. **Server validates and checks ACL** (`src/pool/srv_pool.c:pool_connect_handler`):
   ```c
   // Validate signature
   rc = ds_sec_validate_credentials(cred, &token);

   // Check pool ACL permissions
   rc = ds_sec_pool_get_capabilities(flags, credp, &owner,
                                     acl_entry->dpe_val_ptr, &sec_capas);
   ```

5. **Server creates pool handle** with cached capabilities and returns `poh`

#### Step 2: Container Open (Uses Authenticated Pool Handle)

```c
// Open container - uses credential from pool connection
daos_handle_t coh;
rc = daos_cont_open(poh, cont_uuid, DAOS_COO_RW, &coh, NULL, NULL);
```

**What happens** (`src/container/srv_container.c`):

1. Client sends container open RPC using the pool handle (`poh`)
2. Server extracts credential from the pool handle (already authenticated)
3. Server checks **container ACL** against the user's identity
4. Server creates container handle with cached **container capabilities**
5. Server returns `coh` (container handle UUID)

**No re-authentication** - the credential from pool connect is reused.

#### Step 3: DFS Mount (Uses Authenticated Handles)

```c
// Mount DFS filesystem using authenticated handles
dfs_t *dfs;
rc = dfs_mount(poh, coh, O_RDWR, &dfs);
```

**What happens** (`src/client/dfs/mnt.c:dfs_mount_int`):

```c
int dfs_mount_int(daos_handle_t poh, daos_handle_t coh, int flags, ...)
{
    dfs_t *dfs;

    D_ALLOC_PTR(dfs);

    // Store authenticated handles
    dfs->poh = poh;  // Pool handle with cached capabilities
    dfs->coh = coh;  // Container handle with cached capabilities

    // Query container properties (uses authenticated coh)
    rc = daos_cont_query(coh, NULL, prop, NULL);

    // Open superblock and root directory (uses authenticated coh)
    rc = open_sb(coh, ...);

    *_dfs = dfs;
    return 0;
}
```

**No authentication** - `dfs_mount()` uses the already-authenticated handles to query metadata and set up the filesystem structure.

### Complete Authentication Flow Diagram

```
Application            libdfs              libdaos             Agent             Server
    │                    │                    │                  │                 │
    │                                                                              │
    ├─ Step 1: Pool Connection (AUTHENTICATION HAPPENS)                           │
    │                    │                    │                  │                 │
    │ daos_pool_connect  │                    │                  │                 │
    ├───────────────────────────────────────>│                  │                 │
    │                    │ dc_sec_request_creds()                │                 │
    │                    │                    ├────────────────> │                 │
    │                    │                    │  SO_PEERCRED     │                 │
    │                    │                    │  (uid=1000)      │                 │
    │                    │                    │  Sign with RSA   │                 │
    │                    │                    │<──────────────── │                 │
    │                    │ (signed credential)│                  │                 │
    │                    │                    │                  │                 │
    │                    │ pool_connect RPC   │                  │                 │
    │                    │                    ├─────────────────────────────────> │
    │                    │                    │                  │  Validate sig   │
    │                    │                    │                  │  Check pool ACL │
    │                    │                    │                  │  Cache capas    │
    │                    │                    │<───────────────────────────────── │
    │<───────────────────────────────────────┤                  │                 │
    │   poh (handle with cached capabilities)│                  │                 │
    │                    │                    │                  │                 │
    │                                                                              │
    ├─ Step 2: Container Open (USES AUTHENTICATED POOL HANDLE)                    │
    │                    │                    │                  │                 │
    │ daos_cont_open(poh)│                    │                  │                 │
    ├───────────────────────────────────────>│                  │                 │
    │                    │ cont_open RPC      │                  │                 │
    │                    │ (uses poh cred)    ├─────────────────────────────────> │
    │                    │                    │                  │  Check cont ACL │
    │                    │                    │                  │  Cache capas    │
    │                    │                    │<───────────────────────────────── │
    │<───────────────────────────────────────┤                  │                 │
    │   coh (handle with cached capabilities)│                  │                 │
    │                    │                    │                  │                 │
    │                                                                              │
    ├─ Step 3: DFS Mount (NO AUTHENTICATION, USES AUTHENTICATED HANDLES)           │
    │                    │                    │                  │                 │
    │ dfs_mount(poh,coh) │                    │                  │                 │
    ├──────────────────> │                    │                  │                 │
    │                    │ daos_cont_query    │                  │                 │
    │                    ├──────────────────────────────────────────────────────> │
    │                    │ (uses coh)         │                  │  Check capas    │
    │                    │<────────────────────────────────────────────────────── │
    │<──────────────────┤                    │                  │                 │
    │   dfs (local struct with metadata)      │                  │                 │
    │                    │                    │                  │                 │
    │                                                                              │
    ├─ Step 4: File Operations (CAPABILITY CHECKS ONLY)                           │
    │                    │                    │                  │                 │
    │ dfs_open("file")   │                    │                  │                 │
    ├──────────────────> │                    │                  │                 │
    │                    │ daos_obj_open()    │                  │                 │
    │                    ├──────────────────> │                  │                 │
    │                    │                    │ obj RPC (uses coh)                 │
    │                    │                    ├───────────────────────────────────>│
    │                    │                    │                  │  Check capas    │
    │                    │                    │                  │  (cached in coh)│
    │                    │                    │                  │  No re-auth!    │
    │                    │                    │<───────────────────────────────────┤
    │                    │<──────────────────┤                  │                 │
    │<──────────────────┤                    │                  │                 │
    │                    │                    │                  │                 │
```

### Key Takeaways

1. **No special authentication** - libdfs uses standard libdaos authentication
2. **Authentication in Step 1 only** - `daos_pool_connect()` does full auth (agent, signature, ACL)
3. **Step 2 reuses credentials** - `daos_cont_open()` uses pool handle's credential
4. **Step 3 uses authenticated handles** - `dfs_mount()` queries metadata using authenticated container handle
5. **Step 4 is fast path** - File operations use cached capabilities (bitwise checks)

## Important Code Locations

### Client Side (C)

- `src/client/api/agent.c` - Agent socket connection setup
- `src/security/cli_security.c` - Credential request via dRPC (`dc_sec_request_creds`)

### Agent Side (Go)

- `src/control/cmd/daos_agent/security_rpc.go` - Credential creation (`getCredential`)
- `src/control/security/auth/auth_sys.go` - Token signing/verification
- `src/control/security/domain_info.go` - `SO_PEERCRED` extraction (`DomainInfoFromUnixConn`)
- `src/control/security/config.go` - ClientUserMap implementation

### Server Side Validation (Mixed)

**C (Data Plane)**:
- `src/security/srv_acl.c` - Validation entry point (`ds_sec_validate_credentials`, `ds_sec_pool_get_capabilities`)
- `src/security/acl.c` - ACL permission matching (`get_acl_permissions`, `calculate_acl_perms`)

**Go (Control Plane)**:
- `src/control/server/security_rpc.go` - Signature verification (`processValidateCredentials`)

### Handle Management (C)

- `src/include/daos_srv/pool.h` - `ds_pool_hdl` structure definition
- `src/pool/srv_target.c` - Handle hash table operations (`ds_pool_hdl_lookup`)

### Capability Checks (C)

- `src/security/srv_acl.c` - Capability checking helpers (`ds_sec_pool_can_*`, `ds_sec_cont_can_*`)
- `src/container/srv_container.c` - Container operation checks
- `src/security/srv_internal.h` - Capability bit definitions

### Protocol Definitions

- `src/proto/security/auth.proto` - Protobuf definitions for `Sys`, `Token`, `Credential`
