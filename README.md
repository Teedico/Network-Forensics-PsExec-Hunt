# Network-Forensics-PsExec-Hunt
# CyberDefenders PsExec Hunt CTF Challenge Analysis

## Objective

This project documents the analysis of network traffic from the CyberDefenders "PsExec Hunt" Blue Team CTF challenge. The primary goal was to use Wireshark to dissect a provided packet capture (`.pcapng` file) to trace the steps of an attacker who gained initial access and used PsExec for lateral movement within the network, answering specific questions posed by the challenge.

## Skills Learned/Demonstrated

-   **Network Traffic Analysis:** Analyzing packet captures (`.pcapng`) to identify suspicious activities and reconstruct event timelines.
-   **Wireshark Proficiency:** Effectively using Wireshark features including display filters, conversation statistics, following streams, and packet detail inspection.
-   **Protocol Analysis:** Understanding and interpreting various network protocols relevant to the attack, including IPv4, TCP, UDP, SMB/SMB2, NTLMSSP, and LLMNR.
-   **Digital Forensics:** Applying forensic techniques to network data to uncover attacker TTPs (Tactics, Techniques, and Procedures).
-   **Lateral Movement Detection:** Identifying indicators of lateral movement using tools like PsExec by analyzing network shares (ADMIN$, IPC$) and service creation artifacts (PSEXESVC.exe).
-   **CTF Problem Solving:** Systematically addressing challenge questions using evidence derived from network traffic analysis.

## Tools Used

-   **Wireshark:** The primary tool for packet capture analysis. (Version 4.3.0 or similar indicated in references).
-   **CyberDefenders Platform:** The source of the CTF challenge and lab files.
-   **VMware Workstation Player (or similar):** Virtual machine environment used to run the analysis tools (implied by window titles).
-   **Kali Linux (or similar Linux distribution):** Operating system used for analysis (implied by window titles and environment).

## Analysis Steps & Findings

The following steps were taken to analyze the `psexec-hunt.pcapng` file and answer the challenge questions:

1.  **Initial Access IP Identification (`10.0.0.130`):**
    *   Used Wireshark's **Statistics -> Conversations -> IPv4** tab.
    *   Identified the IP address `10.0.0.130` as suspicious due to having a significantly higher packet/byte count in conversations compared to other hosts, suggesting it was the source of the initial attack activity.
2.  **First Pivot Hostname Identification (`SALES-PC`):**
    *   Applied the Wireshark display filter `ip.src == 10.0.0.130` to isolate traffic originating from the attacker machine.
    *   Followed relevant TCP streams and examined SMB/SMB2 packets involved in authentication.
    *   Inspected the details of packet 131 (an SMB2 Session Setup Response), specifically within the NTLMSSP Challenge section, to find the **Target Name** field, which contained the hostname `SALES-PC`.
       ![Wireshark Conversations showing high traffic for 10.0.0.130 and Wireshark packet details for Packet 131 showing Target Name SALES-PC](https://github.com/Teedico/Network-Forensics-PsExec-Hunt/blob/3b3fe88bbf19956d1b094d1e1f76cee97d2442eb/Screenshot%20(38).png)

3.  **Authentication Username Identification (`ssales`):**
    *   Continued analysis of packet 131 (SMB2 Session Setup Response).
    *   Examined the **SMB2 Header** details within this packet.
    *   Identified the username `ssales` within the **Session Id** parameter field information.
        ![Wireshark packet details for Packet 131 showing Session ID with ssales username](placeholder_image_url_step3_session_id.png)

4.  **Service Executable Identification (`PSEXESVC.exe`):**
    *   Examined the SMB traffic flow between the attacker (`10.0.0.130`) and the first victim (`10.0.0.133`).
    *   Searched or filtered for SMB2 Create Request/Response packets related to file transfers or service creation.
    *   Identified packets explicitly mentioning `PSEXESVC.exe` being created or accessed on the target machine (`SALES-PC`).
        ![Wireshark packet list showing SMB2 Create Request for PSEXESVC.exe](placeholder_image_url_step4_psexesvc_create.png)

5.  **Service Installation Share Identification (`ADMIN$`):**
    *   Located the SMB2 packets associated with the creation/transfer of `PSEXESVC.exe` (e.g., packet 144 Create Request).
    *   Inspected the **SMB2 Header** details for these packets.
    *   Identified the network share used by checking the **Tree Id** parameter, which corresponded to the `\\<target_ip>\ADMIN$` share.
        ![Wireshark packet details showing Tree ID corresponding to ADMIN$ share](placeholder_image_url_step5_admin_share.png)

6.  **PsExec Communication Share Identification (`IPC$`):**
    *   Filtered the communication specifically between the attacker and the first victim: `tcp and ip.addr==10.0.0.130 && ip.addr==10.0.0.133`.
    *   Navigated to the beginning of the relevant communication sequence after initial authentication.
    *   Examined the first **Tree Connect Request** packet sent from the attacker (packet 134).
    *   Inspected the **SMB2 Tree Connect Request** details and found the **Sharename** requested was `\\10.0.0.133\IPC$`.
        ![Wireshark packet details for Tree Connect Request showing IPC$ share](placeholder_image_url_step6_ipc_share.png)

7.  **Second Pivot Hostname Identification (`Marketing-PC`):**
    *   Changed the focus to traffic originating from the *first victim machine* (`SALES-PC`) using the filter `ip.src == 10.0.0.131`.
    *   Observed **LLMNR (Link-Local Multicast Name Resolution)** protocol traffic.
    *   Examined packet 19, an LLMNR Standard query.
    *   Inspected the **Queries** section within the LLMNR details and found the hostname being queried was `Marketing-PC`, indicating an attempt by the attacker (controlling `SALES-PC`) to resolve this name for further lateral movement.
        ![Wireshark packet details for LLMNR query targeting Marketing-PC](placeholder_image_url_step7_llmnr_query.png)

## References

1.  Wireshark Foundation. Wireshark User's Guide Version 4.3.0. Retrieved from https://www.wireshark.org/docs/wsug_html_chunked/
2.  FireCompass Technologies Inc. (2023, November 24). Attack & Defend LLMNR: A Widespread Shadow Network Discovery Protocol. Retrieved from https://www.firecompass.com/blog/attack-defend-llmnr-a-widespread-shadow-network-discovery-protocol/
