# 💥 LetsDefend: Critical SharePoint RCE and Machine Key Theft (CVE-2025-53770)

## 🛡️ Project Focus: Authentication Bypass and Remote Code Execution (RCE) Triage

This project documents the end-to-end investigation of a zero-day exploitation attempt against a Microsoft SharePoint server, demonstrating proficiency in correlating Web Traffic logs (SIEM) with Endpoint Detection and Response (EDR) telemetry to fully map the attacker's multi-stage attack chain. The severity of this was critical, with a CVSS score of 9.8.

---

## 🎯 Key Learning Objectives

* **Multi-Stage Analysis:** Correlating network (HTTP POST) and endpoint (PowerShell/CMD) logs to reconstruct a complex kill chain.
* **Vulnerability Context:** Understanding how unauthenticated requests targeting `ToolPane.aspx` can achieve authentication bypass.
* **Post-Exploitation Triage:** Detecting advanced techniques, including on-the-fly C# compilation (`csc.exe`), webshell deployment, and system secret extraction via .NET reflection.
* **Threat Validation:** Using third-party intelligence (VirusTotal) to confirm the malicious nature of dropped files.
* **Impact Assessment:** Recognizing the critical threat posed by the theft of ASP.NET **Machine Keys** (used for forging auth tokens).

---

## 🔎 Incident Workflow and Findings

The investigation began with a suspicious activity alert targeting the SharePoint server, which was quickly linked to active exploitation of CVE-2025-53770.

### Stage 1: Initial Access and Authentication Bypass

| Log Source | Evidence | Analysis |
| :--- | :--- | :--- |
| **Web Traffic** | Unauthenticated `HTTP POST` request targeting `/ToolPane.aspx`. | This is the signature of the exploit, leveraging a known flaw to bypass SharePoint's authentication mechanism. |
| **Web Traffic** | Spoofed `Referer` header set to `/layouts/SignOut.aspx`. | **Evasion Technique:** Attempt to make the malicious request appear as a benign post-logout activity. |
| **Web Traffic** | Large, encoded data payload (7699 bytes). | Highly suspicious activity indicating the injection of a command or script payload into the request body. |

### Stage 2: Establishing Persistence and Tool Deployment

Following the successful execution via the ToolPane exploit, EDR telemetry captured a sequence of highly malicious post-exploitation commands.

| EDR Event | Command Executed | Attacker's Intent |
| :--- | :--- | :--- |
| **PowerShell** | Decoded and executed ASPX script (via reflection). | **Key Extraction:** The script uses .NET reflection to access private configuration and dump the server's **ValidationKey** and **DecryptionKey**. |
| **CMD** | `csc.exe /out:C:\Windows\Temp\payload.exe C:\Windows\Temp\payload.cs` | **On-the-fly Compilation:** Creates and compiles a custom C# executable (`payload.exe`) on the server. |
| **CMD** | `cmd.exe /c echo <WebShell> > C:\Program Files\Common Files\...\spinstall0.aspx` | **Persistence:** Writes a malicious ASPX webshell directly into a web-accessible directory (`/layouts/`). |

### Stage 3: Threat Validation and Critical Impact

The analyst performed crucial validation steps to confirm the severity and full compromise.

1.  **Webshell Analysis:** The hash of the deployed webshell (`spinstall0.aspx`) was submitted to VirusTotal.
    * **Result:** **34/64 security vendors flagged it as malicious**, confirming the successful deployment of a remote downloader/command execution tool.
2.  **Secret Theft Confirmation:** The final observed PowerShell command directly invoked the `.NET` method to extract the cryptographic machine keys.
    * **Impact:** Theft of these keys allows the attacker to **forge authentication cookies** for any user, potentially leading to full compromise and data exfiltration without needing passwords.

---

## 📝 Analyst Summary and Resolution

| Action Taken | Outcome / Justification |
| :--- | :--- |
| **Classification** | **True Positive** (Successful RCE and key theft confirmed). |
| **Severity** | **Critical** - Unauthenticated RCE leading to credential/secret theft. |
| **Final Note** | Attacker executed a multi-stage attack to establish persistent access and steal critical machine secrets (ValidationKey, DecryptionKey). |
| **Containment (Recommendation)** | Immediate isolation of the SharePoint server and patching of the known vulnerability (CVE-2025-53770). Reset all sensitive keys and review all user sessions. |

The incident demonstrates a complete kill chain, emphasizing that successful defense requires correlating telemetry across both network and endpoint security layers.
