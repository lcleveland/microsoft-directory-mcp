# OData filters for entra_* lists

entra_* list actions take four optional arguments:

| Argument | Becomes | Notes |
|---|---|---|
| `filter` | `$filter` | passed through as written |
| `query` | `$search="displayName:…" OR "mail:…"` | quick name or mail lookup |
| `sort` | `$orderby` | e.g. `displayName desc` |
| `fields` | `$select` | only these properties come back |

The server adds `ConsistencyLevel: eventual` and `$count=true` for you when the
request needs them (see Advanced queries). Never pass headers or `$count` yourself.

## Syntax

| Form | Meaning |
|---|---|
| `prop eq 'text'`, `prop eq true`, `prop eq 5` | equals |
| `prop ne 'text'` | not equals (advanced) |
| `not(expr)` | negation (advanced) |
| `a and b`, `a or b`, `(…)` | combine |
| `startsWith(prop,'pre')` | prefix; there is no `contains` on directory objects |
| `endsWith(prop,'@example.com')` | suffix (advanced); only `mail`, `otherMails`, `userPrincipalName`, `proxyAddresses` |
| `prop in ('a','b')` | any of |
| `prop ge 2026-01-01T00:00:00Z`, `le`, `gt`, `lt` | ordering |
| `prop eq null`, `prop ne null` | missing / present |
| `coll/any(x:x eq 'v')` | a multi-valued property holds a value |
| `assignedLicenses/$count eq 0` | collection size (advanced) |

- Strings are in single quotes; double a quote inside one: `'O''Brien'`.
- GUIDs, dates (ISO 8601 UTC), numbers, booleans and `null` are **not** quoted.
- Property names are the Graph names the results show (`userPrincipalName`,
  `accountEnabled`, …). Operators are lowercase.

## Advanced queries

`ne`, `not`, `endsWith`, `/$count`, and `filter` together with `sort` need Graph's
advanced query mode; so does `query` (`$search`). The server turns it on. Its index
is **eventually consistent**: an object created or changed in the last minutes may
be missing or stale, so read it back with a get by id.

Advanced queries work only on directory objects: users, groups, devices,
applications, service principals, contacts and administrative units. Audit logs,
sign-ins, Intune and Conditional Access have their own, narrower `$filter`
support: keep their filters to `eq`, `ge`/`le` on times, `startsWith` and `and`.

## Common filters

| Question | Filter |
|---|---|
| disabled users | `accountEnabled eq false` |
| guests | `userType eq 'Guest'` |
| synced from AD | `onPremisesSyncEnabled eq true` |
| cloud-only | `onPremisesSyncEnabled ne true` |
| created since a date | `createdDateTime ge 2026-01-01T00:00:00Z` |
| unlicensed users | `assignedLicenses/$count eq 0` |
| has a licence (by SKU id) | `assignedLicenses/any(l:l/skuId eq 00000000-0000-0000-0000-000000000000)` |
| UPN in a domain | `endsWith(userPrincipalName,'@example.com')` |
| security groups | `securityEnabled eq true and mailEnabled eq false` |
| Microsoft 365 groups | `groupTypes/any(t:t eq 'Unified')` |
| dynamic groups | `groupTypes/any(t:t eq 'DynamicMembership')` |
| Windows devices | `operatingSystem eq 'Windows'` |

`$search` tokenizes only `displayName` and `description`; on other properties it is
a prefix match. A `&` in `query` is a known Graph problem: use `filter` instead.
