# TryHackMe: Benign

Write-up for the TryHackMe **Benign** room.

## Task 1: Introduction

- Start the lab machine and wait for it to fully boot.
- Click **Open machine in browser**.
- Use the `win_eventlogs` index for the investigation.

### Known users

| Department | Users |
| --- | --- |
| IT | James, Moin, Katrina |
| HR | Haroon, Chris, Diana |
| Marketing | Bell, Amelia, Deepak |

## Task 2: Investigate the Windows Event Logs

### Q1. How many logs were ingested from March 2022?

**Method**

- Query the `win_eventlogs` index and filter for events from March 2022.
- Use the following Splunk query:

```text
index=win_eventlogs earliest="03/01/2022:00:00:00" latest="04/01/2022:00:00:00"
```

- Count the returned events.

**Answer:** `13959`

### Q2. What is the name of the imposter account observed in the logs?

**Method**

- Compare the usernames in the logs with the known users.
- Group the results by username and hostname to identify anomalies:

```text
index=win_eventlogs | stats values(HostName) as HostName by UserName
```

- The results show `Amel1a`, which is similar to the legitimate username
  `Amelia` but contains a `1` instead of an `i`.

**Answer:** `Amel1a`

### Q3. Which HR user was observed running scheduled tasks?

**Method**

- Filter for HR hosts and search for `schtasks` activity:

```text
index=win_eventlogs HostName=HR* schtasks | table UserName, HostName, CommandLine
```

- Review the results to identify the user who created a scheduled task.

**Answer:** `Chris.Fort`

### Q4. Which HR user executed a system process to download a payload?

**Method**

- Search HR logs for common download-capable LOLBins:

```text
index=win_eventlogs HostName=HR* | search certutil OR PowerShell OR MSHTA OR Bitsadmin | table UserName, HostName, CommandLine, ProcessName
```

- The results show that `haroon` executed a `certutil` command to download a
  payload.

**Answer:** `haroon`

### Q5. Which LOLBin was used to download the payload from the internet?

**Method**

- Review the command identified in the previous question.
- The process used to bypass security controls and download the payload was
  `certutil`.

**Answer:** `certutil`

### Q6. On what date was this binary executed by the infected host?

**Method**

- Search for execution of the downloaded binary:

```text
index=win_eventlogs | search benign.exe
```

- Inspect the event timestamp.

**Answer:** `2022-03-04`

### Q7. Which third-party site was accessed to download the malicious payload?

**Method**

- Review the `CommandLine` field from the `benign.exe` event.
- The command shows that the host accessed `controlc[.]com`.

**Answer:** `controlc[.]com`

### Q8. What is the name of the file saved on the host from the C2 server?

**Method**

- Review the command line associated with the download.
- The file saved on the host was named `benign.exe`.

**Answer:** `benign.exe`

### Q9. What pattern was contained in the suspicious file?

The suspicious file contained malicious content matching the pattern
`THM{..........}`.

**Method**

- Use the full URL from the command line in a safe URL analysis service.
- The page hosted at the C2 URL contains `flag.txt`.
- Inspecting the file reveals the flag.

**Answer:** `THM{KJ&*H^B0}`

### Q10. What URL did the infected host connect to?

**Method**

- Review the command line used to download the payload.
- The infected host connected to the following URL.

**Answer:** `hxxps[://]controlc[.]com/e4d11035`

## Afterthoughts and Conclusions

- The investigation identified an imposter account by comparing usernames with
  known legitimate accounts.
- The attacker used the trusted system process `certutil` to bypass security
  controls and download a payload.
- The activity was traced from the initial download through execution of
  `benign.exe` and communication with the C2 server.
- Monitoring command-line activity, scheduled tasks, and network connections
  can help detect similar malicious behavior.
