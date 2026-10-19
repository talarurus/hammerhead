# Working on Hammerhead Core

Work only in this standalone Core workspace. Do not edit the protected Hammerhead branch, R1G/R1I candidates, labs or historical evidence. Base commit: `4fa1018b13ed4b8b6af194a326105e098dc8118f`.

The product has exactly six native checks and no Git execution path. Changes that add Git metadata execution require a separate product/security decision; no flag or build fallback belongs here. Reuse `internal/fs`, checks, collector and reporters. Do not weaken rooted filesystem authority or guarded reads.

Use disposable synthetic fixtures exclusively. Run `make check` and the packaged smoke demo. The required native acceptance matrix is in `release/ACCEPTANCE.md`; sandbox failures are failures/pending acceptance, not passes. Preserve actual failure records. Native acceptance has passed; preserve and reuse its evidence for unchanged tested inputs. The original acceptance recipe is `release/qualify-macos.sh`.

Public distribution requires explicit founder approval of the prepared unsigned prerelease. Do not push, tag, publish a release or update talarurus.com as part of this checkpoint.
