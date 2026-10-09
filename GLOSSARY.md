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

**Global catalog**:
A domain controller that also holds a partial, read-only copy of every domain in the forest; used only to find which domain holds an object, never for lists.
_Avoid_: GC server, forest index

**PDC emulator**:
The one domain controller per domain that processes lockouts and receives password changes first; where that domain's writes go.
_Avoid_: primary DC, PDC (alone), master DC

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

**Counterpart**:
The object on the other side that the same identity is linked to: the Entra object of a synced AD object, or the AD object of a synced Entra one.
_Avoid_: twin, mirror, linked object

**Source of authority**:
The side where an object's attributes may be changed; the forest for a synced object, the tenant for a cloud-only one.
_Avoid_: master, owner, origin

### Server behaviour

**Capability**:
A named class of write the operator opts into; writes outside an enabled capability do not exist for the client.
_Avoid_: permission, verb flag

**Protected target**:
An object the server never writes, whatever capabilities are enabled: a tier-0 object in the forest (counting DnsAdmins and the operator's `--protected-groups` as tier-0 groups), or a role-assignable group, or a user holding an admin role (or in or owning a role-assignable group, or owning an app or service principal) in the tenant.
_Avoid_: privileged object, admin object, tier-0 (alone)

**Tool group**:
A named set of tools the operator can enable or disable together.
_Avoid_: module, feature, category
