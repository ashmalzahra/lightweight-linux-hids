# System Architecture

## 1. Architectural Goal

The system uses a modular pipeline that separates host observation, event normalisation, rule evaluation, alert generation, and storage. This separation allows monitors and rules to be tested independently and makes the reason for each alert inspectable.

## 2. Processing Pipeline

```text
Linux data source
       |
       v
Monitor / collector
       |
       v
Normalised Event
       |
       v
Rule Engine
       |
       v
Structured Alert
       |
       v
JSON Lines storage