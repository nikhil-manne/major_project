# Cyber Range Test Target

This is a deliberately weak scanner/integration test fixture, not a production image.
It uses an end-of-life Node.js 18 base image and runs as root so configuration and
image scanners have realistic issues to evaluate. Exact CVE results depend on the
current image digest and scanner database.

## Files
- `Dockerfile` — image definition to upload to the Cyber Range.
- `app.js` — harmless HTTP service used as the running target.

## Local build and smoke test
Run only in an isolated local test environment:

```sh
docker build -t cyber-range-test-target:local .
docker image inspect cyber-range-test-target:local --format '{{.Id}}'
docker run --rm -p 127.0.0.1:3000:3000 cyber-range-test-target:local
```

Then visit `http://127.0.0.1:3000/` and `http://127.0.0.1:3000/health`.

## Important
- Do not expose this test target to the public internet.
- Do not use it for production.
- Upload the Dockerfile together with `app.js` (or upload this folder as an archive)
  if the platform supports build-context archives. A Dockerfile alone cannot build
  an image when it references files that were not uploaded.
- A successful build is not proof of a vulnerability. Preserve scanner output,
  image digest, and tool/database versions as evidence.
