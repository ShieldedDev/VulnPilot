# VulnPilot Architecture

## Overview

VulnPilot is a Flask-based security assessment application that provides a scan workflow, result storage, and report output for authorized web-app and infrastructure testing.

The project is intentionally modularized around a few core responsibilities:

- web app and user session workflows
- scan orchestration and safety configuration
- scanner modules for reconnaissance and validation
- normalized vulnerability and evidence handling
- reporting and persistence

## Core Layers

### 1. Application Layer

Files:
- app.py

This layer manages:
- authentication
- dashboard and scan lifecycle
- API responses for scan progress and results
- report download endpoints

### 2. Configuration and Safety Layer

Files:
- modules/config.py

This layer centralizes the runtime settings used by scanners and workers. It stores defaults for:
- timeout values
- retry counts
- concurrency
- rate limits
- per-target scope controls
- user-agent and proxy settings

### 3. Finding Model Layer

Files:
- modules/finding.py

This layer defines the normalized vulnerability schema used by the application. It ensures each finding contains:
- title
- severity
- confidence
- target and endpoint
- evidence list
- remediation guidance
- CVSS metadata
- CWE and CVE references

### 4. Scanner Layer

Files:
- modules/scanner.py

This is the main reconnaissance and vulnerability analysis engine.

It currently includes:
- HTTP request handling
- technology detection
- crawl and subdomain checks
- common directory fuzzing
- service detection
- basic header and SSL observations
- XSS and SQLi candidate detection with evidence capture

### 5. Persistence Layer

Files:
- modules/database.py

Stores:
- user accounts
- scan metadata
- scan results as serialized JSON
- per-user history

### 6. Reporting Layer

Files:
- modules/report_generator.py

Generates:
- JSON reports
- PDF style reports

## Architectural Principles

- evidence over assumptions
- safer defaults over aggressive scanning
- modular config over hard-coded constants
- normalized findings over ad hoc dictionaries
- authorized testing only

## Planned Evolution

The project is moving toward a more formal platform architecture with:
- discovery engine
- fingerprinting engine
- vulnerability validation layer
- CVE / exploit intelligence providers
- risk scoring engine
- reporting pipeline
