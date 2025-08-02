# DNS C2 Detection via Entropy and Z-Score (T1071.004)

## Description

This project detects potential DNS-based Command and Control (C2) activity by analyzing DNS query behavior. It focuses on identifying anomalies such as long domain names, high entropy (randomness), and irregular time intervals between queries — characteristics often seen in DNS tunneling and beaconing attacks.

The detection technique is mapped to the MITRE ATT&CK technique **T1071.004 – Application Layer Protocol: DNS**.

---

## Use Case

DNS tunneling is a stealthy technique used by attackers to exfiltrate data or communicate with infected hosts using DNS queries. This project simulates and detects such activity using:

- Domain length analysis
- Entropy estimation
- Time-based anomaly detection using Z-scores
- Safe domain filtering using lookups

---

## Key SPL Logic

The SPL search uses the following key logic:

- Extracts domain length and estimates entropy
- Calculates time intervals between DNS queries by source IP
- Computes Z-score to highlight deviations from typical behavior
- Filters out known/safe domains via a lookup file
- Flags anomalies based on multiple combined conditions

---

## MITRE Mapping

- **Tactic:** Command and Control  
- **Technique:** Application Layer Protocol: DNS  
- **Technique ID:** T1071.004

---

## Output Fields

- `src_ip`: Source IP making the DNS queries  
- `query_name`: The suspicious DNS domain queried  
- `domain_length`: Total characters in the domain  
- `entropy`: Estimated randomness of the domain (simulated)  
- `interval`: Time gap from previous query by the same IP  
- `z_score`: Deviation from average domain length  
- `Tactic`, `Technique`, `Technique_ID`: MITRE-aligned fields

---



##  SPL Detection Logic

```spl
index="dns_project"
| eval domain_length = len(query_name)
| eval subdomain = lower(mvindex(split(query_name, "."), 0))
| eval entropy = ln(domain_length) * ((random() % 100)/100)
| sort src_ip _time
| streamstats current=f window=1 last(_time) as prev_time by src_ip
| eval interval = _time - prev_time
| eventstats avg(domain_length) as avg_len stdev(domain_length) as stdev_len
| eval z_score = (domain_length - avg_len) / if(stdev_len > 0, stdev_len, 1)
| lookup safe_domains.csv domain AS query_name OUTPUT domain AS matched
| where isnull(matched) AND domain_length > 30 AND entropy > 2
| eval Tactic="Command and Control", Technique="Application Layer Protocol: DNS", Technique_ID="T1071.004"
| table _time src_ip query_name domain_length entropy interval z_score Tactic Technique Technique_ID
```

## Notes

- Entropy is estimated using a randomized approximation — for production use, replace with a true Shannon entropy calculation.
- This is a simulation project to demonstrate detection logic for SOC and detection engineering portfolios.
