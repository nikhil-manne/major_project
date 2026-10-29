# Demonstration Guide: Honest Local Simulation

## Purpose

Demonstrate the current local prototype without implying that simulated activity is a real attack or that unverified external services are operational.

## Pre-demo checklist

- Start the backend in the intended local simulation profile.
- Start the frontend if its dependencies install successfully.
- Confirm the health endpoint reports the expected mode.
- Use a fresh local test database or a documented test dataset.
- Confirm that no real secrets are visible in the terminal, UI, or recording.

## Suggested walkthrough

1. **Health and mode:** show the API health response and explicitly identify simulation mode.
2. **Authentication:** sign in with local development credentials configured for this machine; show role restrictions through the UI/API.
3. **Lab policy screening:** upload a test lab definition and show that it is policy-checked, not built into an image.
4. **Simulated scenario:** run a scenario and show the execution mode and counts for live, simulated, blocked, and inconclusive steps.
5. **Detection:** show local rule evaluation against the events generated in the simulation.
6. **Coverage:** show that simulated events do not count as verified live ATT&CK coverage.
7. **Readiness score:** explain that the score is heuristic and not a production certification.
8. **Archive and replay:** show event archive/replay metadata. State that the supplied demo reported packet capture unavailable and zero packets.
9. **CI gate:** show `INCONCLUSIVE` for a simulation-only run and explain why missing live evidence must not pass silently.
10. **Copilot:** identify the deterministic fallback as a demo fallback, not a verified LLM/RAG service.

## Recorded evaluation values

The supplied HTTP demonstration log records one run with 0 live steps, 5 simulated steps, 1 blocked step, 7 detections, 0 covered live techniques, an unavailable packet capture with 0 packets, 6 replayed attack events, and 6 replay detections. These values describe that specific run only and are not performance benchmarks.

## Do not claim during the demo

- That an exploit succeeded against a real target when the scenario was simulated.
- That real network traffic was captured when the packet count is zero.
- That all ATT&CK techniques are covered.
- That the readiness score certifies production security.
- That the image builder, Kubernetes sandbox, Keycloak SSO, or external event pipeline is live unless that exact workflow has been tested in the demo environment.

## Future live demonstration

Once the live environment is ready, use an authorized disposable target and show attack execution, real telemetry, detection linkage, evidence-backed ATT&CK coverage, archive integrity, and an enforced CI decision. Keep the local simulation walkthrough separate from this live demonstration.
