# Microsoft Directory MCP

An MCP server that lets an MCP client read and, when permitted, act on one on-premises Active Directory forest and one Entra ID tenant.

## Language

### Directories

**Forest**:
The single on-premises Active Directory forest a server process talks to, spanning one or more domains.
_Avoid_: directory (alone), AD instance

**Domain**:
One Active Directory domain inside the forest; the unit that owns objects and domain controllers.
_Avoid_: realm, naming context (unless meaning the LDAP partition)

**Domain controller**:
A server hosting a domain's copy of the directory that the server process connects to.
_Avoid_: DC server, AD server, LDAP server

**Tenant**:
The single Entra ID organization a server process talks to.
_Avoid_: instance, account, Azure AD, directory (alone)

**Side**:
Either half of the server, AD or Entra; each is configured independently and either may be absent.
_Avoid_: backend, provider, half

### Hybrid identity

**Sync mode**:
How the forest and the tenant are joined: Connect Sync, Cloud Sync, or none (cloud-only).
_Avoid_: hybrid mode, federation

**Synced object**:
An Entra object whose source is an AD object, brought across by sync.
_Avoid_: hybrid object, linked object

**Source of authority**:
The side where an object's attributes may be changed; the forest for a synced object, the tenant for a cloud-only one.
_Avoid_: master, owner, origin

### Server behaviour

**Capability**:
A named class of write the operator opts into; writes outside an enabled capability do not exist for the client.
_Avoid_: permission, verb flag

**Tool group**:
A named set of tools the operator can enable or disable together.
_Avoid_: module, feature, category
