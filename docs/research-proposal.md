# Research Proposal

## Lightweight Linux Host Intrusion Detection System

**Status:** Draft

## 1. Problem Statement

Linux hosts generate security-relevant information through system logs, authentication records, process information, filesystem state, account configuration, and scheduled-task configuration. Individually, these data sources describe events occurring on a host, but they do not automatically determine whether a sequence of events is suspicious. Host-based intrusion detection systems can monitor characteristics such as system logs, running processes, file access and modification, and configuration changes [1].

Host-based intrusion detection systems address this problem by monitoring activity on an individual machine and analysing the collected information for signs of potentially harmful behaviour. Existing security platforms provide broad detection and management capabilities, but their scale and complexity can make it difficult for a beginner to examine how individual observations are transformed into security alerts.

This project will design and evaluate a deliberately limited, transparent, rule-based HIDS for Linux. The system will prioritise understandable detection logic, configurable rules, measurable resource consumption, and reproducible experiments. It is intended as a research and educational prototype rather than a replacement for production security platforms.

## 2. Research Question

Can a lightweight, configurable, rule-based host intrusion detection system accurately detect selected Linux host-level security events while maintaining low computational overhead?

## 3. Aim

The aim of this project is to investigate the effectiveness and limitations of a lightweight rule-based approach to Linux host intrusion detection.

## 4. Objectives

1. Review foundational literature and existing host-based intrusion detection approaches.
2. Design a modular architecture that separates data collection, event normalisation, rule evaluation, alert generation, and storage.
3. Implement monitoring for authentication activity, file integrity, running processes, scheduled tasks, and user or privilege changes.
4. Implement configurable detection rules whose conditions and thresholds can be inspected and modified without changing core program logic.
5. Validate individual components using automated unit and integration tests.
6. Evaluate the system using controlled suspicious and benign scenarios.
7. Measure detection results, false positives, detection latency, CPU utilisation, and memory consumption.
8. Analyse where the rule-based approach succeeds, where it fails, and how configuration choices affect its behaviour.
9. Document the design, methodology, results, limitations, and reproducibility instructions.

## 5. Scope

The prototype will run on a controlled Xubuntu virtual machine and monitor that host only. It will examine the following categories:

- Authentication events.
- Changes to designated files and directories.
- Running-process information.
- Changes to user accounts and privilege-related group membership.
- Changes to cron jobs and selected scheduled-task configuration.

The system will use explicit, configurable rules to generate structured alerts. Evaluation will use authorised activity created inside the isolated virtual-machine laboratory.

## 6. Out of Scope

The following capabilities are outside the project scope:

- Network intrusion detection.
- Malware classification or antivirus functionality.
- Machine-learning-based anomaly detection.
- Automatic blocking or remediation.
- Monitoring multiple hosts from a central server.
- Production deployment or enterprise-scale performance testing.
- Exploitation of public or third-party systems.
- Claims that an alert conclusively proves malicious activity.

## 7. Expected Contribution

The project will provide a small, inspectable HIDS prototype and an experimental analysis of the trade-offs between detection coverage, rule simplicity, false positives, detection latency, and resource usage in a controlled Linux environment.

## References

[1] K. Scarfone and P. Mell, *Guide to Intrusion Detection and Prevention Systems (IDPS)*, NIST Special Publication 800-94, National Institute of Standards and Technology, 2007. https://doi.org/10.6028/NIST.SP.800-94