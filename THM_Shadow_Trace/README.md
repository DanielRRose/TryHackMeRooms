# TryHackMe: Shadow Trace

This write-up documents the steps and answers for the **Shadow Trace** room.

## Task 1: Analyze the Binary

### 1. What is the architecture of `windows-update.exe`?

Use ExifTool to inspect the executable's metadata. Run it from its installation directory or provide the full path to `exiftool.exe`.

For example, from the ExifTool directory:

```cmd
exiftool.exe ..\..\Desktop\windows-update.exe
```

In the output, `Machine Type: AMD AMD64` and `PE Type: PE32+` identify a 64-bit executable.

```text
File Type                       : Win64 EXE
Machine Type                    : AMD AMD64
PE Type                         : PE32+
```

**Answer:** 64-bit

### 2. What is the SHA-256 hash of `windows-update.exe`?

Use `certutil` to calculate the SHA-256 hash. Specify `SHA256` explicitly; otherwise, `certutil` defaults to SHA-1.

From the directory containing the file, run:

```cmd
certutil -hashfile windows-update.exe SHA256
```

**Answer:** `b2a88de3e3bcfae4a4b38fa36e884c586b5cb2c2c283e71fba59efdb9ea64bfc`

### 3. Identify the URL in the file that can be used as an IOC

Open `windows-update.exe` in PEStudio. You can drag the file into the application or choose **File → Open**. Under **Indicators**, look for the `string > url-pattern` entry.

**Answer:** `http://tryhatme.com/update/security-update.exe`

### 4. Identify a domain that can be used as an IOC

In PEStudio's **Strings** tab, search for `tryhatme`. The relevant string is:

```text
responses.tryhatme.com
```

Alternatively, search the executable's strings from PowerShell:

```powershell
strings .\windows-update.exe | findstr "tryhatme"
```

**Answer:** `responses.tryhatme.com`

### 5. Decode the flag associated with the suspicious domain

Search the executable's strings for `tryhatme`, using PEStudio or the PowerShell command from the previous question. The relevant output includes:

```text
tryhatme.com/VEhNe3lvdV9nMHRfc29tZV9JT0NzX2ZyaWVuZH0=
responses.tryhatme.com
```

Copy the Base64 value after `tryhatme.com/` and decode it with CyberChef using the **From Base64** operation.

```text
Input:  VEhNe3lvdV9nMHRfc29tZV9JT0NzX2ZyaWVuZH0=
Output: THM{you_g0t_some_IOCs_friend}
```

**Answer:** `THM{you_g0t_some_IOCs_friend}`

### 6. What socket communication library is loaded by the binary?

In PEStudio, open the **Imports** tab and look for networking-related functions such as `socket`, `connect`, `send`, or `recv`. The associated library is:

**Answer:** `WS2_32.dll`

## Task 3: Analyze the Alerts

Click **View Site** to open the static page for this task.

### 7. Identify the malicious URL triggered by `powershell.exe`

Find the process that used `powershell.exe` and inspect its command. The command contains this Base64-encoded string:

```text
aHR0cHM6Ly90cnloYXRtZS5jb20vZGV2L21haW4uZXhl
```

Decode it with CyberChef using the **From Base64** operation.

**Answer:** `https://tryhatme.com/dev/main.exe`

### 8. Identify the malicious URL in the alert triggered by `chrome.exe`

Find the process that used `chrome.exe` and inspect its command. It contains decimal-encoded data:

```text
104,116,116,112,115,58,47,47,114,101,97,108,108,121,115,101,99,117,114,101,117,112,100,97,116,101,46,116,114,121,104,97,116,109,101,46,99,111,109,47,117,112,100,97,116,101,46,101,120,101
```

Decode it with CyberChef using the **From Decimal** operation.

**Answer:** `https://reallysecureupdate.tryhatme.com/update.exe`

### 9. What is the name of the file saved in the alert triggered by `chrome.exe`?

Review the command associated with `chrome.exe` and identify the `.txt` file.

**Answer:** `test.txt`

## Conclusion

This completes the TryHackMe **Shadow Trace** room.
