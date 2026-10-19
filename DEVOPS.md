# DevOps: release and deployment

Flux on NKP deploys nai-guardrail-extproc from an immutable OCI artifact
in GHCR. CI builds the image and the artifact, and never commits or
pushes to Git.

POC scope: one cluster, one `dev` environment, everything in `nai-system`.

## The flow

```
merge to main
   │
   ▼
GitHub Actions (release.yaml)
   1. build + push image      ghcr.io/rhapsody008/nai-guardrail-extproc:<full sha>
   2. pin its digest into deploy/kustomization.yaml   ← CI workspace only, never committed
   3. push deploy/ as artifact ghcr.io/rhapsody008/manifests/nai-guardrail-extproc:<sha7>
   4. move tag  dev ──► <sha7>
   │
   ▼
NKP cluster, namespace nai-system
   GitOps Source (Git, path ./gitops)      ── applies ──► gitops/nai-guardrail-extproc.yaml
   OCIRepository  nai-guardrail-extproc    ── polls tag dev every 2m
   Kustomization  nai-guardrail-extproc    ── applies the artifact → Deployment, Service, EnvoyExtensionPolicy
```

The two folders are read differently:

| Folder | Read by | Change it when |
| --- | --- | --- |
| `deploy/` | CI packages it; Flux reads it **from GHCR, never from Git** | Any manifest change: env vars, replicas, policy settings. It ships with the next release. |
| `gitops/` | Flux, from Git through the NKP GitOps source | Changing which tag the cluster tracks, the sync interval, or the target namespace. Takes effect on merge, with no release. |

Only the artifact in GHCR contains the pinned image digest.
`deploy/kustomization.yaml` in Git always maps the image by name only.

## What each trigger does

| Trigger | Build image | Push image | Push artifact + move `dev` |
| --- | --- | --- | --- |
| Pull request to `main` | ✅ | ❌ | ❌ |
| Push to `main`, including a merged PR | ✅ | ✅ `:<full sha>` | ✅ `:<sha7>`, then `dev` |
| Push of a `v*.*.*` tag | ✅ | ✅ `:<sha>`, `:X.Y.Z`, `:X.Y` | ❌ |
| Manual run on `main` | ✅ | ✅ | ✅ |
| Manual run on another branch | ✅ | ✅ `:<sha>` | ❌ |

**A pull request never pushes anything.** The GHCR login step and the
image push are skipped for `pull_request` events. The four Flux steps
(set up the Flux CLI, pin the digest, push the artifact, promote to
`dev`) also require `github.ref == refs/heads/main`. A PR run ends after
"Build and push" with `push: false`. It only checks that the Dockerfile
and the Go code build before you merge. Merging causes a separate push
event on `main`, and that run does the release.

Pushes that only change `gitops/**` or `**.md` don't trigger a release.

**After a merge to main:** once the CI run finishes, Flux sees the new
`dev` tag within 2 minutes. To skip the wait, run
`flux reconcile source oci nai-guardrail-extproc -n nai-system`.

## Rollback

Rolling back means moving the `dev` tag back to an earlier artifact. No
Git revert is needed.

```bash
# list artifacts (tags are short commit SHAs)
flux list artifacts oci://ghcr.io/rhapsody008/manifests/nai-guardrail-extproc

# point dev at a known-good one
flux tag artifact oci://ghcr.io/rhapsody008/manifests/nai-guardrail-extproc:<sha7> --tag dev

# apply now instead of waiting up to 2m
flux reconcile source oci nai-guardrail-extproc -n nai-system
```

The next merge to `main` moves `dev` forward again. To keep the rollback
in place, revert the bad commit on `main` too.

Retagging needs `write:packages` on GHCR. Log in first with
`echo $GHCR_PAT | docker login ghcr.io -u rhapsody008 --password-stdin`.

To freeze the cluster on one release whatever gets merged, change
`gitops/nai-guardrail-extproc.yaml` from `ref.tag: dev` to
`ref.digest: sha256:<artifact digest>`, and merge that change.

## First-time cluster setup

These are manual steps; CI and the repo don't do them.

1. **Make the GHCR packages public.** The first CI run creates
   `manifests/nai-guardrail-extproc` as a **private** package. In GitHub,
   go to Packages → `manifests/nai-guardrail-extproc` → Package settings
   → Change visibility → Public. The image package is already public.
   That's why the manifests have no `secretRef` or `imagePullSecrets`.
2. **Create the CAI API key Secret.** It is never stored in Git:

   ```bash
   kubectl create secret generic guardrail-extproc-creds \
     --namespace nai-system \
     --from-literal=GUARDRAIL_API_KEY='<your real key>'
   ```
3. **Remove the manually applied objects.** If the Deployment, Service
   or policy were applied by hand from `nai-tools`, Flux takes them over
   by name, and no delete is needed. Delete anything that isn't in
   `deploy/` anymore.
4. **Create the GitOps source in NKP:**

   | Field | Value |
   | --- | --- |
   | Name | `nai-guardrail-extproc-gitops` |
   | Repository URL | `https://github.com/rhapsody008/nai-guardrail-extproc` |
   | Git ref | Branch `main` |
   | Path | `./gitops` (never `./`) |
   | Git secret | none (public repo) |
5. **Check permissions.** The Flux objects live in `nai-system`, not in
   a project namespace. Whatever identity NKP's Kustomization uses for
   this source must be able to create `OCIRepository` and Flux
   `Kustomization` objects in `nai-system`. The Flux Kustomization in
   `gitops/` must in turn be able to create a Deployment, a Service and
   an `EnvoyExtensionPolicy` there.
6. **Check egress.** Nodes and Flux controllers need outbound access to
   `ghcr.io`, and the extproc pods to the CAI endpoint.

Until the first release reaches `main`, the OCIRepository reports
`tag dev not found`. That is expected.

## Verification

Work through the stages top to bottom; the first one that fails is
where the problem is. `flux get all -n nai-system` shows stages 3–6
together.

| # | Stage | Check | Typical failure |
| --- | --- | --- | --- |
| 1 | Image pushed | Actions run is green; `ghcr.io/rhapsody008/nai-guardrail-extproc:<sha>` exists | Missing `packages: write` |
| 2 | Artifact pushed | `flux pull artifact oci://ghcr.io/rhapsody008/manifests/nai-guardrail-extproc:dev -o /tmp/x`, then `grep sha256 /tmp/x/kustomization.yaml` | Digest step failed; check the "Pin digest" log |
| 3 | NKP fetches the repo | `flux get sources git -A` | Wrong branch or URL |
| 4 | `gitops/` applied | `flux get kustomizations -A` | Path left as `./`; RBAC denied in `nai-system` |
| 5 | Artifact pulled | `flux get sources oci -n nai-system` | Package still private; no egress; `dev` tag not created yet |
| 6 | Manifests applied | `flux get kustomizations -n nai-system` | Build error; health check timeout (3m) |
| 7 | Pods running | `kubectl -n nai-system get pods -l app=guardrail-extproc` | `CreateContainerConfigError`: Secret `guardrail-extproc-creds` missing |

Confirm the cluster runs a digest-pinned image:

```bash
kubectl -n nai-system get deploy guardrail-extproc -o jsonpath='{..image}'
# → ghcr.io/rhapsody008/nai-guardrail-extproc@sha256:…
```

## Guarantees to keep

- `grep -rE "git (commit|push)" .github/` returns nothing.
- No file in Git contains `@sha256:` for the app image.
- `kubectl kustomize deploy` and `kubectl kustomize gitops` both build.
- All Flux objects live in `nai-system` and don't reference sources in
  other namespaces.
