# ADR-0001 — Separate offline Compliance Core and Data Platform adapter

Status: ACCEPTED (engineering) · 2026-11-05

## Context
Existing Data Platform provides acquisition, crawl, extraction, evidence, SDK.
Legal rules and commercial accounts are product-specific. Reimplementation
would fork security and persistence logic across Arvectum applications.

## Decision
Offline core uses only standard library and has no tenant/payment/network
dependencies. An optional integration consumes Data Platform's public
AcquisitionEngine/AcquisitionRequest and validates public target URLs.
Commercial service calls the same core through a versioned API contract.

## Consequences
Strong reuse and deterministic CI. The existing platform's browser/HTTP
transport does not constitute hardened SSRF protection against DNS rebinding
or browser subresource requests. Do not expose arbitrary-target scanning
as a public multi-tenant endpoint until network-layer isolation is proven.
