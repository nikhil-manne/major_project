# Positioning: Prototype vs. Traditional SIEM

## Purpose

This comparison explains the intended difference between this project and an enterprise SIEM. It is a conceptual positioning document, not a benchmark or claim of feature parity. Vendor capabilities change and should be cited from current official documentation in any external submission.

## Intended distinction

A traditional SIEM is generally used to collect, search, correlate, alert on, and investigate security telemetry. This project aims to add a controlled validation loop: run an approved scenario against an isolated build or lab, observe the resulting telemetry, test detections, preserve evidence, and make an explicit release decision.

The intended differentiator is the link between attack evidence, detection evidence, replay, coverage reporting, and CI policy—not a claim that any one of those features is unique.

## Current maturity boundary

| Capability | Project's current evidence-backed position |
|---|---|
| Local attack workflow | Simulation is locally tested; live execution not verified. |
| Detection evaluation | Local rules are tested against available events; real sensor integration not verified. |
| ATT&CK coverage | Reporting exists; simulated events are excluded from verified coverage. |
| Replay | Stored event replay is locally tested; real PCAP replay is not verified. |
| CI gate | Simulation returns INCONCLUSIVE; live release enforcement is not verified. |
| Dashboard | Source exists; production frontend build remains unverified in the supplied evaluation. |

## Claims to avoid

Do not claim the project replaces a mature SIEM, achieves better detection accuracy, has complete ATT&CK coverage, or provides production-grade automated release assurance without comparative testing and live evidence.

## How to make a fair comparison

For any final report, define the same test environment, data volume, attack scenarios, ground truth, response metrics, and failure conditions for every compared platform. Cite current vendor documentation for third-party product features. Label this project's capabilities as designed, implemented, locally verified, or integration unverified.
