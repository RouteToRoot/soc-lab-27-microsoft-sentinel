# Lab 27 — Microsoft Sentinel: Cloud SIEM Detection

**Platform:** Microsoft Azure / Microsoft Sentinel  
**Difficulty:** Intermediate  
**Status:** Complete

## Overview
Deployed Microsoft Sentinel as a cloud-native SIEM in Azure. Configured a Windows Server 2025 VM to forward Security Events via the Azure Monitor Agent (AMA), wrote a custom KQL detection rule for failed login attempts (Event ID 4625), simulated a brute force attack via RDP, and investigated the resulting incidents in Microsoft Defender XDR.

## What I Did
- Deployed Log Analytics Workspace (RTR-LAW) and enabled Microsoft Sentinel
- Configured Windows Security Events data connector via Azure Monitor Agent
- Created a Data Collection Rule (RTR-DCR-WindowsEvents) and attached RTR-WinVM
- Verified log ingestion by querying the SecurityEvent table in Log Analytics
- Wrote a KQL scheduled query rule to detect brute force login attempts (Event ID 4625)
- Simulated a brute force attack via RDP using invalid credentials
- Investigated 7 incidents in Microsoft Defender XDR — confirmed 30 failed attempts from IP 64.183.42.233

## Tools & Technologies
- Microsoft Sentinel
- Microsoft Defender XDR
- KQL (Kusto Query Language)
- Azure Monitor Agent (AMA)
- Azure Virtual Machines (Windows Server 2025)
- Log Analytics Workspace

## MITRE ATT&CK
- Tactic: Credential Access (TA0006)
- Technique: Brute Force (T1110)

## Portfolio Page
[View Full Lab Writeup](https://routetoroot.github.io/soc-lab-27-microsoft-sentinel)
