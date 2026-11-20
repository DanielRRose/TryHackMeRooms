# TryHackMe: Log Analysis with SIEM

Write-up for the **Log Analysis with SIEM** room. Start the lab machine before beginning the tasks. Splunk searches below use the room's lab data.

## Task 1: Introduction

Start the lab machine before proceeding.

## Task 2: Benefits of SIEM for Analysts

### Q1. What is the process of linking data from multiple sources to identify relationships between events?

**Method:** Relate the process to piecing separate events together to form a complete picture.

**Answer:** Correlation

### Q2. What is the process of collecting and storing logs from multiple systems in one location?

**Method:** Identify the process of bringing data together in a unified location for analysis.

**Answer:** Centralisation

## Task 3: Log Sources Overview

### Q3. What is the process of converting logs from different formats into a single format?

**Method:** Look for the term describing how data is organized to conform to a standard.

**Answer:** Normalisation

### Q4. Which log source type can detect the execution of a malicious script?

**Method:** Identify the log source that provides detailed visibility into activity on an individual system.

**Answer:** Host-based logs

## Task 4: Windows Logs

Investigate a suspicious connection from host `WIN-105` on port `5678`. Logs are in index `task4`.

### Q5. Which IP address was the connection established with?

**Method:** Search for port `5678` and display the destination IP:

```spl
index=task4 DestinationPort=5678 | table _time SourceIp DestinationIp DestinationPort Protocol
```

**Answer:** `10.10.114.80`

### Q6. Which process initiated the suspicious connection?

**Method:** Add the `Image` field to the port search:

```spl
index=task4 DestinationPort=5678 | table _time Image SourceIp DestinationIp DestinationPort Protocol
```

**Answer:** `SharePoInt.exe`

### Q7. What is the MD5 hash of the malicious process?

**Method:** Search for the process and inspect the process-creation event (`EventCode=1`):

```spl
index=task4 Image=*SharePoInt.exe* | table _time EventCode ComputerName ParentImage ParentProcessId Image Hashes
```

**Answer:** `770D14FFA142F09730B415506249E7D1`

### Q8. What scheduled task was created on the system?

**Method:** Search `WIN-105` command lines for `schtasks`:

```spl
index=task4 ComputerName=WIN-105 CommandLine=*schtasks* | table UtcTime ComputerName ParentImage Image CommandLine Description
```

The `/tn` argument specifies the task name.

**Answer:** `Office365 Install`

## Task 5: Linux Logs

Investigate possible persistence through creation of a `remote-ssh` account. Logs are in index `task5`.

### Q9. When was the `remote-ssh` account created?

**Method:** Search `auth.log` for account-creation and account-name references:

```spl
index=task5 source="auth.log" | sort + _time | search "useradd" OR "remote-ssh"
```

**Answer:** `2025-08-12 09:52:57`

### Q10. Which user escalated privileges to root before the account was created?

**Method:** Search `auth.log` for `su` activity and review events immediately before account creation:

```spl
index=task5 source="auth.log" | sort + _time | search "su"
```

**Answer:** `jack-brown`

### Q11. Which IP address did `jack-brown` log in from?

**Method:** Search for the user's successful SSH login:

```spl
index=task5 source="auth.log" | search "jack-brown" AND "Accepted password"
```

**Answer:** `10.14.94.82`

### Q12. How many failed login attempts occurred before the successful login?

**Method:** Search `auth.log` for failed password events for `jack-brown` and compare their timestamps with the successful login:

```spl
index=task5 source="auth.log" | sort + _time | search "jack-brown" AND "Failed password"
```

**Answer:** `4`

### Q13. Which port was the persistence mechanism configured to connect to?

**Method:** Search syslog for cron jobs and possible script or shell activity:

```spl
index=task5 sourcetype=syslog | search "cron" OR "CRON" OR "python*" OR "perl" OR "ruby" OR ".sh" OR "bash" OR "nc"
```

The results show a Python reverse shell launched through a root cron job.

**Answer:** Port `7654` (destination IP `10.10.33.31`)

## Task 6: Web Application Logs

Investigate a spike in web-server activity. Logs are in index `task6`.

### Q14. Which URI path had the highest number of requests?

**Method:** Count requests by URI path and sort from highest to lowest:

```spl
index=task6 | stats count by uri_path | sort - count
```

**Answer:** `/wp-login.php` (907 requests)

### Q15. Which IP address was the source of the activity?

**Method:** Count requests to the URI by client IP:

```spl
index=task6 uri_path="/wp-login.php" | stats count by clientip | sort - count
```

**Answer:** `10.10.243.134`

### Q16. How can this activity be classified?

**Method:** Chart requests over time from the source IP to check the request rate:

```spl
index=task6 uri_path="/wp-login.php" clientip=10.10.243.134 | timechart span=5m count
```

The IP made 586 requests in about a minute, consistent with a rapid password-guessing attempt.

**Answer:** Brute-force attack

### Q17. Which tool did the threat actor use?

**Method:** Inspect the user agent for requests from the source IP:

```spl
index=task6 uri_path="/wp-login.php" clientip=10.10.243.134 | table _time referer_domain clientip useragent uri_path
```

**Answer:** `WPScan v3.8.28`
