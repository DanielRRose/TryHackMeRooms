# TryHackMe: ItsyBitsy

Write-up for the TryHackMe **ItsyBitsy** room.

## Task 1: Introduction

- Start the lab machine and wait for it to open.
- After the machine is deployed, access Elastic using the provided IP address.
- Open the **Discover** tab and review the available logs.

## Task 2: Scenario - Investigate a Potential C2 Communication Alert

### Q1. How many events were returned for the month of March 2022?

**Method**

- Filter the logs by setting the start date to the first day of March and the end date to the last day of March using the date picker.
- Count the number of events returned.

**Answer:** `1482`

### Q2. What is the IP associated with the suspected user in the logs?

**Method**

- Select the relevant fields for display, including `source_ip`, `source_port`, `destination_ip`, `host`, `method`, `uri`, and `user_agent`.
- Review the `source_ip` field. Almost all events are associated with a single IP address, while a few events have a different source IP.
- Apply a filter for `192.166.65.54` to isolate the anomalous events.
- Inspect the anomalous events. The `host` field is associated with `pastebin[.]com`, a file-sharing platform widely exploited by cybercriminals.

**Answer:** `192.166.65.54`

### Q3. The user's machine used a legitimate Windows binary to download a file from the C2 server. What is the name of the binary?

**Method**

- Inspect the events associated with the suspicious IP.
- Review fields such as `process_name` or `command_line`, and look for an entry that identifies the binary involved.
- The available filter identifies `bitsadmin` in the `user_agent` field.
- A quick search confirms that `bitsadmin` is a legitimate Windows binary used for managing BITS jobs and can be exploited to download files from remote servers.

**Answer:** `bitsadmin`

### Q4. The infected machine connected with a famous file-sharing site in this period, which also acts as a C2 server used by malware authors to communicate. What is the name of the file-sharing site?

**Note:** Enter the defanged domain in the answer.

**Method**

- Inspect the events associated with the suspicious IP.
- Review the `host` field for connections to external domains.
- The anomalous events show `pastebin[.]com`, which was identified earlier.
- A quick search confirms that Pastebin is a well-known file-sharing site often abused by cybercriminals as a C2 server.

**Answer:** `pastebin[.]com`

### Q5. What is the full URL of the C2 to which the infected host is connected?

**Note:** Enter the defanged full URL in the answer.

**Method**

- Inspect the anomalous events associated with the suspicious IP.
- Review the `host` field for the domain and the `uri` field for the path.
- The events contain `pastebin[.]com` in the `host` field and `/yTg0Ah6a` in the `uri` field.
- Combine the host and URI fields to form the complete C2 URL.

**Answer:** `pastebin[.]com/yTg0Ah6a`

### Q6. A file was accessed on the file-sharing site. What is the name of the file accessed?

**Method**

- Navigate to the C2 URL identified in Q5.
- Inspect the file or page content returned by the URL.
- The page contains a file named `secret.txt`.

**Answer:** `secret.txt`

### Q7. The file contains a secret code with the format `THM{_____}`. What is the secret code?

**Method**

- Open the file accessed on the file-sharing site.
- Review the file contents.
- The file contains a single line in the required format.

**Answer:** `THM{SECRET__CODE}`

## Afterthoughts and Conclusions

- The investigation revealed that the infected machine communicated with a C2 server hosted on the well-known file-sharing site `pastebin[.]com`.
- The attacker used the legitimate Windows binary `bitsadmin` to download a file from the C2 server.
- The accessed file contained a secret code in the format `THM{_____}`, which was successfully retrieved.
- This exercise highlights the importance of monitoring network traffic and analyzing anomalous events to identify potential security incidents.
- By connecting network data and key event fields, it is possible to reconstruct the actions taken by the attacker.
