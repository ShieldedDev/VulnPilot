# Module Overview

## app.py

The main Flask application entry point. Handles user auth, scans, progress polling, and report download routes.

## modules/config.py

The shared configuration model for scanner safety and execution settings.

## modules/finding.py

Defines the normalized finding schema used across scan results and reporting.

## modules/scanner.py

Contains the active scanning logic including HTTP requests, technology detection, crawling, and candidate vulnerability checks.

## modules/database.py

SQLite-backed persistence for user accounts and scan records.

## modules/report_generator.py

Creates JSON and PDF-style outputs from scan results.

## templates/

Flask Jinja2 templates for the web interface.

## static/

CSS, JS, and generated report artifacts.

## tests/

Regression tests covering config defaults and normalized findings.
