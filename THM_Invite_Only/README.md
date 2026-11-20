# TryHackMe: Invite Only

Write-up for the **Invite Only** room. This guide follows the investigation in
order, keeping each room question together with its method and answer.

> [!NOTE]
> This write-up is based on the room and the research described below. Room
> content and third-party reports may change over time.

> [!WARNING]
> Perform hands-on analysis only in the authorized TryHackMe lab. Do not visit
> or interact with malicious infrastructure.

## Contents

- [Lab setup](#lab-setup)
- [Questions and walkthrough](#questions-and-walkthrough)
- [Hashes for reference](#hashes-for-reference)
- [Sources](#sources)

## Lab setup

1. Start the TryHackMe room machine and wait for it to become available.
2. Open **TryDetectThis 2.0** from the desktop when the lab is ready.
3. Use the room-provided indicators in the steps below.

## Questions and walkthrough

### Question 1

**What is the name of the file identified with the flagged SHA-256 hash?**

**Method**

1. In TryDetectThis 2.0, paste the room-provided hash into the search bar:
   `5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f`.
2. In the report, inspect the **File** details. The entry shows
   `syshelpers.exe` as a `Win32 EXE`.

**Answer:** `syshelpers.exe`

### Question 2

**What is the file type associated with the flagged SHA-256 hash?**

**Method**

Use the same report as Question 1 and read the file type shown in the **File**
details.

**Answer:** `Win32 EXE`

### Question 3

**What are the execution parents of the flagged hash? List the names
chronologically, using a comma as a separator. Note down the hashes for later
use.**

**Method**

1. Open the flagged sample's report and select **Relations**.
2. Find **Execution Parents**. The entries are `Powershell • 361GJX7J` and
   `Win32 EXE • installer.exe`.
3. Use the names after the type labels, in chronological order.
4. Save the parent hashes for Question 5. They are also listed in
   [Hashes for reference](#hashes-for-reference).

**Answer:** `361GJX7J,installer.exe`

### Question 4

**What is the name of the file being dropped? Note down the hash value for
later use.**

**Method**

1. In the flagged sample's report, open **Relations**.
2. Find **Dropped Files**. The listed file is `unknown • AClient.exe`.
3. Save its hash for reference; it is included in
   [Hashes for reference](#hashes-for-reference).

**Answer:** `AClient.exe`

### Question 5

**Research the second hash in Question 3 and list the four malicious dropped
files in the order they appear (from top to bottom), separated by commas.**

**Method**

1. Search for the `installer.exe` execution-parent hash from Question 3:
   `fa102d4e3cfbe85f5189da70a52c1d266925f3efd122091cdc8fe0fc39033942`.
2. Open **Relations** and scroll to **Dropped Files**.
3. From the listed files, include only those marked malicious, preserving their
   displayed order.

**Answer:** `searchHost.exe,syshelpers.exe,nat1.vbs,runsys.vbs`

### Question 6

**Analyse the files related to the flagged IP. What is the malware family that
links these files?**

**Method**

1. Search for the room's defanged IP, `101[.]99[.]76[.]120`, in
   TryDetectThis 2.0.
2. Open **Relations** and review **Communicating Files** for related hashes.
3. Look up the related hashes or review **Community Comments**. A researcher
   comment references Malpedia and identifies the malware family.

**Answer:** `AsyncRAT`

### Question 7

**What is the title of the original report where these flagged indicators are
mentioned? Use Google to find the report.**

**Method**

1. Search the flagged IP in VirusTotal.
2. Open **Details** and scroll to the Google results section.
3. Follow the Check Point Research result beginning with “From Trust to
   Threat” to read the full report title.

**Answer:** *From Trust to Threat: Hijacked Discord Invites Used for
Multi-Stage Malware Delivery*

### Question 8

**Which tool did the attackers use to steal cookies from the Google Chrome
browser?**

**Method**

Continue reading the Check Point Research report from Question 7 and search
within it for “cookies.” The report discusses Chrome's App-Bound Encryption
(ABE) and describes the tool the attackers adapted to steal cookies.

**Answer:** `ChromeKatz`

### Question 9

**Which phishing technique did the attackers use? Use the report to answer
the question.**

**Method**

In the Check Point Research report, search for “phishing” and review the
section about the phishing website. It describes a user-experience trick that
prompts the visitor to take manual action to “fix” an apparent problem.

**Answer:** `ClickFix`

### Question 10

**What is the name of the platform that was used to redirect a user to
malicious servers?**

**Method**

In the report, find the section titled **“Understanding Discord Invite
Links.”** It describes how the attackers abused invitation links as part of
their phishing activity.

**Answer:** `Discord`

## Hashes for reference

| Indicator | SHA-256 |
| --- | --- |
| Flagged sample (`syshelpers.exe`) | `5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f` |
| Execution parent (`361GJX7J`) | `047c5eec0445746862710d20e50a5dd04510b7e625fa5c1f5d48ce078001c0de` |
| Execution parent (`installer.exe`) | `fa102d4e3cfbe85f5189da70a52c1d266925f3efd122091cdc8fe0fc39033942` |
| Dropped file (`AClient.exe`) | `dd02c105809e4ca41a5489e585ba025eddb89a91703b73a566c9903e6406a08c` |

## Sources

- TryHackMe room: **Invite Only**
- TryDetectThis 2.0, available in the room
- Check Point Research report: *From Trust to Threat: Hijacked Discord
  Invites Used for Multi-Stage Malware Delivery*
