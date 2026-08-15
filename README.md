# Lightweight Linux Host Intrusion Detection System

> **Project status:** Research and development in progress

A lightweight, configurable, rule-based host intrusion detection system for Linux. The project investigates whether selected host-level security events can be detected accurately while maintaining low computational overhead.

## Research Question

Can a lightweight, configurable, rule-based host intrusion detection system accurately detect selected Linux host-level security events while maintaining low computational overhead?

## Planned Monitoring Capabilities

- Authentication activity
- File integrity
- Running processes
- User and privilege changes
- Scheduled-task changes

## Planned System Pipeline

1. Collect host information from defined Linux data sources.
2. Convert raw observations into standardised events.
3. Evaluate events using configurable detection rules.
4. Generate structured alerts when rules match.
5. Store alerts for inspection and experimental analysis.

## Evaluation

The system will be evaluated in an isolated Xubuntu virtual machine using controlled suspicious and benign scenarios. The planned measurements include:

- Detection results by scenario
- False positives and false negatives
- Detection latency
- CPU utilisation
- Memory consumption
- Scenario coverage
- Behaviour under different configurations

## Research Outputs

The completed repository is intended to include:

- Literature review
- Research proposal
- Architecture documentation
- Source code and automated tests
- Experimental methodology
- Raw and processed evaluation results
- Tables and figures
- Technical report
- Reproduction instructions

## Safety and Intended Use

This project is an educational and research prototype. Experiments must be conducted only on systems that the user owns or is explicitly authorised to test. An alert indicates that a rule matched observed activity; it does not conclusively prove malicious behaviour.

## Documentation

The current research proposal is available in [`docs/research-proposal.md`](docs/research-proposal.md).

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE).