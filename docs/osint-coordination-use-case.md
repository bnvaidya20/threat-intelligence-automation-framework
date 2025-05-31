# Simulated OSINT Coordination Exercise  
**Cross-Sector Cyber Threat Simulation Anchored in the Threat Intelligence Automation Framework**  
 
---

## Objective

To evaluate the effectiveness of cross-institutional OSINT integration and coordination in responding to a multi-vector cyber threat scenario targeting academic and critical infrastructure networks.

This exercise simulates a **ransomware campaign** using phishing domains and malicious PDFs targeting a university research lab and a regional healthcare provider. The goal is to stress-test **OSINT ingestion, enrichment, dissemination, and coordination** across sectors.

---

## Stakeholders

| Sector         | Participants                                                                 |
|----------------|-------------------------------------------------------------------------------|
| Government     | Public Safety Canada – National Cyber Coordination Office *(Simulated)*     |
| Academia       | University of Ottawa – Cybersecurity Research Lab                           |
| Private Sector | Healthcare SOC team, simulated TI vendors *(e.g., Recorded Future APIs)*     |
| Intelligence   | MISP, OpenCTI, Shodan, AbuseIPDB, VirusTotal                                 |
| Coordination   | Slack (shared comms), GitHub (shared IOCs), STIX/TAXII sharing infrastructure |

---

## Coordination Role

**Binod Vaidya – OSINT Integration Coordinator**

- Designed attack simulation using historical ransomware TTPs and threat actor behaviors.
- Implemented **Threat Intelligence Automation Framework**:
  - Automated ingestion of STIX, CSV, and JSON feeds.
  - IOC enrichment using AbuseIPDB and VirusTotal.
  - Mapped indicators to MITRE ATT&CK TTPs.
- Enabled multi-stakeholder communication via Slack & shared dashboards.
- Led post-exercise debrief and documentation of lessons learned.

---

## Key Outcomes

| Focus Area            | Outcome                                                                 |
|-----------------------|-------------------------------------------------------------------------|
| Indicator Discovery   | 37 high-confidence IOCs discovered; 22 not known to some stakeholders   |
| Deconfliction         | Ownership of 6 overlapping incidents clarified using OpenCTI tags       |
| Coordination Efficiency | Incident triage time reduced by 40% through shared dashboard access   |
| Gaps Identified       | Academic institutions lacked formal TI participation protocols          |
| Strategic Impact      | Draft proposal created for Academic Threat Exchange Protocol (ATXP)    |

---

## Toolchain

- **Platforms**: Dockerized MISP, OpenCTI, Streamlit-based dashboards, Elasticsearch
- **Automation**: Python-based ingestion + enrichment via cron jobs
- **Standards**: MITRE ATT&CK, NIST CSF, CVSS v3, STIX 2.1/TAXII
- **Dashboards**: Executive summary and tactical visualizations per sector

---

## Follow-Up Recommendations

- Formalize academic–government TI information-sharing MOUs.
- Develop SOPs and playbooks for joint crisis simulations.
- Automate IOC triage prioritization using ML-based threat scoring.


---

## Contact

**Author**: Binod Vaidya 

**Email**: bvaidya@uottawa.ca