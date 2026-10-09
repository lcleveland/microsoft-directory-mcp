# LDAP filters for ad_* searches

`filter` takes a raw LDAP filter (RFC 4515). The ad_user, ad_group, ad_computer and
ad_object tools AND it with their object class, and `query` adds an `(anr=…)` name
lookup. ad_api uses the filter as given.

Every list searches each domain's own domain controllers, never the global catalog,
so any attribute works in a filter. Attribute names are the LDAP names the results
show (`sAMAccountName`, `pwdLastSet`, …); matching is case-insensitive.

## Syntax

| Form | Meaning |
|---|---|
| `(attr=value)` | equals |
| `(attr=pre*)`, `(attr=*mid*)` | wildcard (substring) |
| `(attr=*)` | has any value |
| `(attr>=value)`, `(attr<=value)` | ordering (there is no `>` or `<`) |
| `(&(a)(b))`, `(\|(a)(b))`, `(!(a))` | and, or, not |

A bare `attr=value` is wrapped in parentheses for you.

Escape these characters inside a value: `*` → `\2a`, `(` → `\28`, `)` → `\29`,
`\` → `\5c`. DN values in a filter are written as-is apart from that escaping.

## Values

- **Times** are compared in their stored form, not RFC 3339:
  - `whenCreated`, `whenChanged`: generalized time, `20260101000000.0Z`.
  - `pwdLastSet`, `lastLogonTimestamp`, `accountExpires`, `lockoutTime`: FILETIME,
    the count of 100 ns ticks since 1601-01-01 UTC. Unix seconds `s` become
    `(s + 11644473600) * 10000000`; 2026-01-01T00:00:00Z is `134116992000000000`.
- **Booleans** are `TRUE` / `FALSE`.

## Matching rules

- Bit set: `(userAccountControl:1.2.840.113556.1.4.803:=2)` matches when every bit of
  2 is set (803 is AND, 804 is OR).
- Nested membership: `(memberOf:1.2.840.113556.1.4.1941:=CN=Admins,OU=Groups,DC=example,DC=com)`
  matches direct and nested members. It can be slow on large forests.

## Common filters

| Question | Filter |
|---|---|
| disabled accounts | `(userAccountControl:1.2.840.113556.1.4.803:=2)` |
| enabled accounts | `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` |
| password never expires | `(userAccountControl:1.2.840.113556.1.4.803:=65536)` |
| must change password at next logon | `(pwdLastSet=0)` |
| locked out (since a time) | `(lockoutTime>=134116992000000000)` |
| no logon since a time | `(lastLogonTimestamp<=134116992000000000)` |
| never logged on | `(!(lastLogonTimestamp=*))` |
| created since a date | `(whenCreated>=20260101000000.0Z)` |
| protected by AdminSDHolder | `(adminCount=1)` |
| has an SPN (kerberoastable user) | `(servicePrincipalName=*)` |
| in an OU (and below) | use ad_api with `base` set to the OU's DN |
| security groups | `(groupType:1.2.840.113556.1.4.803:=2147483648)` |
| Windows servers | `(operatingSystem=*Server*)` |

`lastLogonTimestamp` replicates lazily and can be up to 14 days behind the real
last logon.
