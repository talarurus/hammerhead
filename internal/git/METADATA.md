# Private Git metadata capability (A2-R3B1)

Preimplementation security contract, recorded before source changes:

1. Native discovery and checked copies precede queries. Every Git child starts
   with a scanner-owned GIT_DIR; original config is only an explicit inert parser
   input. Generated config contains fixed literals and canonical typed values.
2. The config parser receives --no-includes. Every include directive is refused.
3. Filter, transport, credential, hook and fsmonitor definitions are refused.
   No helper definition is generated. Whole-index admission rejects gitlinks;
   hooks/fsmonitor are disabled and lazy fetching is disabled at startup.
4. Refusal is terminal for Git evaluation. Compatibility APIs use the same
   capability; the low-level process runner is private and requires it.
5. Objects are copied, never alternated, linked or borrowed. Only bounded
   ordinary SHA-1 loose objects and paired .pack/.idx files are admitted.
6. HOME, XDG_CONFIG_HOME, GIT_DIR, GIT_WORK_TREE and the entire child environment
   are constructed explicitly, including bootstrap/config/index queries.
7. --no-lazy-fetch and GIT_NO_LAZY_FETCH=1 apply to every child.
8. Finite config/layout/index admission refuses unknown semantics. Ambient user
   and system attributes/ignore data must be provably absent; uncertainty refuses.
   A fixed var GIT_ATTR_SYSTEM query against generated bootstrap policy obtains
   the installed Git's runtime system path without loading attributes.
9. Required failures discard incomplete status counts, preserve available Git,
   and map to partial GIT-002 / scan / exit 2 through existing reporting.
10. Native traversal/checks and prior findings remain independent and unchanged.

The index is copied from a checked handle; its bytes, size, permission bits and
nanosecond mtime are preserved and verified. Relevant original identities are
rechecked after evaluation. Git continues to perform content comparisons.

Trust is in installed Git, its runtime, caller executable search policy and the
private scanner allocation. Same-UID compromise, Git parser memory safety,
uninterruptible filesystem I/O and atomic worktree snapshots are not promised.
R1 namespace observation and R2 native mutation reporting remain in force.

Reviewed source: upstream Git v2.54.0 and v2.47.3 builtin/var.c, attr.c, dir.c,
path.c, builtin/config.c, builtin/ls-files.c, read-cache.c and git.c, plus the
A2-R3A/B0 source traces. var GIT_ATTR_SYSTEM invokes git_default_config only
against generated policy and returns git_attr_system_file(); it does not read
that attributes file. Unlike an assumed /etc path, this handles runtime prefixes.
XDG defaults use nonempty XDG_CONFIG_HOME, otherwise HOME/.config, on both
platforms. Global/system *configuration* remains disabled as in A2-R2. Configured
attributes/excludes paths are refused. Exact Apple Git-157 vendor source remains
unavailable; installed helper-free differential evidence is required and is not
an active-helper security proof.

## Supported profile and resource costs

Ordinary owned repositories with SHA-1 object IDs, index versions 2–4, ordinary
stage entries and at most the TREE cache extension are supported. Unknown
optional index extensions are refused even when Git would ignore them. Assume
unchanged, skip-worktree, intent-to-add, sparse/split indexes and gitlinks refuse.
The envelope walker checks framing, flags, extensions and checksum only; Git
owns interpretation of paths, revisions, objects and status. No status is
inferred from native stat data.

The finite configuration policy is encoded in projectConfig. Remote URL/fetch,
branch remote/merge, alias and identity assignments are inert because this query
profile uses builtins and exact refs, performs no transport, writes no commits,
and never requests upstream shorthand. They are dropped rather than serialized.
Reflog policy is also inert because optional locks and writes are disabled.
Every other accepted setting has a finite boolean, enum or decimal domain.

Inert branch remote/merge keys use the first and final config-key dots as
section/variable boundaries, preserving dotted subsection names. The supported
branch-name subset is at most 255 ASCII bytes with nonempty alphanumeric,
underscore or hyphen components separated by single dots or slashes; leading
hyphens and slash components ending in .lock refuse. Values are discarded,
never interpreted as commands, paths, references or generated configuration.

Objects are opaque checked copies of loose objects and paired .pack/.idx files.
No hardlinks, alternates, promisor data or live borrowing is permitted. A2-R3B3
also copies exact pack-<40 lowercase hex>.rev/.mtimes bytes alongside complete
ordinary pack/index pairs, and standalone SHA-1 multi-pack-index v1. Sidecar
signatures/version/hash and finite MIDX chunk identifiers are admitted before
object queries. MIDX chunk framing and pack-name membership are checked: every
PNAM entry must be a pack-<40 lowercase hex>.idx with its complete copied pair.
No path from a MIDX may escape the private store. Git still owns object, offset,
checksum and sidecar-body interpretation; this gate does not fsck unused data.

The fixed queries do not require recovery exports or valid maintenance sidecars
when complete ordinary pack/index data is present. However, malformed MIDX data
can cause fatal Git errors. Production retains sidecar bytes instead of silently
omitting that error. Reverse indexes have an in-memory fallback; cruft mtimes
serve retention/expiry, not object membership. Cruft pack objects are still copied
in full. These facts do not authorize ignoring .promisor or unknown metadata.

Only lost-found/{commit,other}/<40 lowercase hex> regular owned recovery exports
are recognized, including empty directories. Checked bounded copies use inert
input.lost-found.* filenames; no lost-found namespace is made live. Source file
and directory observations, copy budgets and cleanup apply unchanged. Each
recovery export and sidecar has the existing 64 MiB object-file ceiling.
Dumb-transport info/refs and objects/info/packs remain inert checked copies.
Unknown names, .bitmap, .keep, commit-graph, MIDX v2/incremental chains and unknown
chunks/versions/hashes refuse. Config, index and all other admission policy remain
unchanged. Upstream v2.54.0 supports MIDX v2, but it is outside this narrow shared
v1 profile; installed Apple Git-157 fixtures generate v1. Exact vendor source
correspondence remains an explicit assumption.

Shared preparation limits: 128 MiB copied bytes, 100,000 enumerated entries,
512 accounted descriptors, 256 path components/ancestor steps, 32 refs levels,
10 seconds. Each file has a smaller bound: config/HEAD/individual refs 1 MiB,
repository attributes/excludes 2 MiB, index or packed refs 32 MiB, individual
object/pack files 64 MiB; index plus refs have a combined 32 MiB bound. Budget
exhaustion refuses. The 128 MiB aggregate is retained as a reviewed ceiling, not
a compatibility promise for arbitrary repositories. Private generated data and
bounded Git output are additional allocations. Copies use a 64 KiB buffer.

Descriptor accounting reserves namespace observation, transient copying and
process pipes. The existing outer engine observer is separately bounded by the
same 256-component limit; together with the native root the Git collection stays
below the B0 1024-descriptor starting ceiling. Actual process-wide descriptors
also include unrelated runtime/caller resources, which are outside this budget.
Closed directory handles remain accounted until final cleanup. Entry count and
copy bytes are cumulative, not reset per subtree. Queries share an eight-child
limit (three preparation children plus at most five snapshot queries), a 30-second
evaluation window and 16 MiB aggregate output, with existing 10-second per-child,
4 MiB stdout and 64 KiB stderr bounds. Output may exceed the aggregate by at most
one bounded child before refusal. Cleanup has a two-second checked deadline and
removes only scanner-created manifest paths, in reverse order, without recursive
deletion. A kernel-blocked I/O operation cannot be forcibly interrupted.

Before status, the copied index's bytes, size, mode and nanosecond mtime are
verified again. After evaluation, original inode, type, ownership, timestamps,
enumerated directories and namespace bindings are rechecked. Any required check
or cleanup failure produces partial evaluation. Sources need not form an atomic
filesystem snapshot; detected changes refuse, and same-UID hostile interference
with the private allocation remains outside the threat model.

## Review source references

- https://github.com/git/git/blob/v2.54.0/builtin/var.c
- https://github.com/git/git/blob/v2.47.3/builtin/var.c
- https://github.com/git/git/blob/v2.54.0/attr.c
- https://github.com/git/git/blob/v2.47.3/attr.c
- https://github.com/git/git/blob/v2.54.0/dir.c
- https://github.com/git/git/blob/v2.47.3/dir.c
- https://github.com/git/git/blob/v2.54.0/path.c
- https://github.com/git/git/blob/v2.54.0/server-info.c
- https://github.com/git/git/blob/v2.54.0/Documentation/gitformat-index.adoc
- https://github.com/git/git/blob/v2.47.3/Documentation/gitformat-index.txt

## A2-R3B3 maintenance source references

Both pinned versions were inspected: packfile.c, midx.c, pack-revindex.c,
pack-mtimes.c, builtin/fsck.c, builtin/pack-objects.c and gitformat-pack. In
v2.54.0, packed_object_info requests mtimes only through oi->mtimep; in v2.47.3
cruft packing reads them in builtin/pack-objects.c. The fixed snapshot builtins
perform neither expiry nor retention. prepare_midx_pack constructs filesystem
paths from PNAM on both versions, requiring the additional finite-name gate.

- https://github.com/git/git/blob/v2.54.0/packfile.c
- https://github.com/git/git/blob/v2.47.3/packfile.c
- https://github.com/git/git/blob/v2.54.0/midx.c
- https://github.com/git/git/blob/v2.47.3/midx.c
- https://github.com/git/git/blob/v2.54.0/pack-revindex.c
- https://github.com/git/git/blob/v2.47.3/pack-revindex.c
- https://github.com/git/git/blob/v2.54.0/pack-mtimes.c
- https://github.com/git/git/blob/v2.47.3/pack-mtimes.c
- https://github.com/git/git/blob/v2.54.0/builtin/fsck.c
- https://github.com/git/git/blob/v2.47.3/builtin/fsck.c
- https://github.com/git/git/blob/v2.54.0/Documentation/gitformat-pack.adoc
- https://github.com/git/git/blob/v2.47.3/Documentation/gitformat-pack.txt
