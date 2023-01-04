# Hunting and Investigation <!-- omit from toc -->

This hunting guide teaches you how to hunt for adversaries, suspicious activities, suspicious processes, and vulnerabilities using Falcon telemetry in Falcon Long-Term Repository (FLTR). Falcon LTR is powered by the Falcon LogScale technology, formerly known as Humio.

Falcon LTR contains a suite of powerful search tools that allow you to analyze, explore, and hunt for suspicious or malicious activity in your environment. These tools include the pre-made search dashboards, as well as the ability to run custom queries on the LTR Event Search page. This guide focuses mainly on using custom queries to hunt, leveraging the LogScale Platform.

# Before You Begin <!-- omit from toc -->

This guide contains information about how to hunt using Falcon and is tailored specifically towards users running the Falcon sensor on Windows devices. However, a lot of the ideas and concepts also apply to users running the Falcon sensor on Mac or Linux. Depending on the sensor platform, however, the names and descriptions of certain events as well as custom query syntax will vary. We recommend that you read and refer to the `Events Data Dictionary` to learn more about specific events and their variations across platforms. The `Events Data Dictionary` also contains additional custom queries not found in this document that could be useful when hunting.

# Table of Contents <!-- omit from toc -->

- [Overview](#overview)
- [Best practices](#best-practices)
  - [Write specific queries](#write-specific-queries)
  - [ComputerName Lookups](#computername-lookups)
  - [Change views](#change-views)
  - [Filter out benign data](#filter-out-benign-data)
- [Hunting queries](#hunting-queries)
- [Hunting phishing attacks and malicious attachments](#hunting-phishing-attacks-and-malicious-attachments)
- [Hunting configuration and compliance vulnerabilities](#hunting-configuration-and-compliance-vulnerabilities)
- [Hunting firewall anomalies and vulnerabilities](#hunting-firewall-anomalies-and-vulnerabilities)
- [Hunting suspicious network connections](#hunting-suspicious-network-connections)
- [Hunting anomalous behavior](#hunting-anomalous-behavior)
- [Hunting anomalies related to scheduled tasks](#hunting-anomalies-related-to-scheduled-tasks)
- [Hunting suspicious registry changes](#hunting-suspicious-registry-changes)
- [Hunting Java malware, trojans, and exploits](#hunting-java-malware-trojans-and-exploits)
  - [Hunting Java malware and trojans](#hunting-java-malware-and-trojans)
  - [Hunting Java exploits](#hunting-java-exploits)


# Hunting in Falcon LTR <!-- omit from toc -->

# Overview

Hunting with Falcon LTR is straightforward. By using either the pre-made dashboards and reports or by using custom queries on the Search page, you can search for specific events and data points across one, several, or all hosts running the Falcon sensor in your environment.

<img src=./images/search_ui.png width=800>

The data returned in an LTR Events Search query is from the timeframe selected in the Time Filter box in the UI. Most of the queries you run will need to be narrowed down to a smaller timeframe so that results are usable. You then use your search results to understand and evaluate security events happening in your environment.

<img src=./images/time_interval.png width=800>

Before you start hunting with Falcon LTR, however, there are a few concepts and best practices that you should familiarize yourself with, beginning with the queries themselves.

# Best practices

## Write specific queries

All queries in Falcon LTR are powered by the LogScale query language. This document focuses less on teaching you syntax and more on the various behaviors and activities you will be hunting. To learn more about LogScale and LogScale syntax, we recommend that you read the [official documentation](https://library.humio.com/).

Even if you aren’t a LogScale expert, this guide makes it easy to understand what each query does and how you can modify queries to get more value out of them.

Every Falcon sensor is given a unique identifier called an `aid`. Every event emitted from the Falcon Sensor contains this field, and should be considered the primary key for looking up events from a given sensor/machine.

Let’s start with a simple example. Show me a list of processes that executed from the Recycle Bin for a specific aid. 

```
#event_simpleName=ProcessRollup2 aid=?aid ImageFileName=/\$Recycle\.Bin/i
| groupBy(aid, function=collect([SHA256HashData, ImageFileName]), limit=max)
```

Most of the queries in this document can simply be copied and pasted into Events Search with minimal modification required by the user. There are two scenarios where the base queries provided will need to be modified by the user:

- `CAPITALIZED_WORDS` - These usually indicate things you should change.
- Queries with the `?value` syntax, like in the above example: aid=?aid. The `?value` creates a user input.

This is an example of a user input:

<img src=./images/user_entry.png width=800>

In the example above, you should provide an "agent ID" (or "AID" for short), which is a unique ID given to each Falcon sensor. Adding the AID to the query limits the scope of your query to the sensor with that AID and greatly reduces the time and computational cost of your search.

The above query might end up looking like this:

```
#event_simpleName=ProcessRollup2 
| aid=?aid ImageFileName=/\$Recycle\.Bin/i
| groupBy(aid, function=collect([SHA256HashData, ImageFileName]), limit=max)
```

or:

<img src=./images/dashboard_entry.png width=800>

This is just one example, but shows how specificity matters when writing LogScale queries. The more specific you can be when writing a query, the fewer results you will have to sort through and the faster the query will run.

Let’s see how a simple query can be made more useful for you with a few simple modifications. Below is an example query that returns a large amount of data and takes a long time to run. This query returns a list of `SuspiciousDnsRequest` events, the domains to which the requests were made, the host names from which the requests were made, and the number of times the requests were made:

```
#event_simpleName=SuspiciousDnsRequest
| groupBy(aid, function=collect(DomainName), limit=max)
```

The amount of results returned by this query and the time that it takes to run make this query difficult to work with. We can fix both of this by making our query more specific.

Let’s start reducing the number of results by limiting the query to a single AID, which would return a list of `SuspiciousDnsRequest` events that occurred on the host running the Falcon sensor with that particular AID:
  
```
#event_simpleName=SuspiciousDnsRequest 
| aid=?aid
| groupBy([aid, DomainName], limit=max)
```

We can further reduce our results list by specifying a timeframe by using the Time Filter from the UI.

We also know that often times requests made only once or twice, instead of dozens of times, are often more likely to be suspicious. We can limit our results to a specific number of suspicious requests. In this example, we’ll say that we only want to see domains to which fewer than three suspicious requests were made. We can do this by adding the event count condition:

```
#event_simpleName=SuspiciousDnsRequest 
| aid=?aid 
| groupBy([aid, DomainName], limit=max)
| _count < 3
```

Alternatively, we could reduce the number of results further by returning only the top 20 or bottom 20 results based on the number of requests made:

```
#event_simpleName=SuspiciousDnsRequest  
| top([aid, DomainName], limit=20)
```

Bottom 20 results:

```
#event_simpleName=SuspiciousDnsRequest  
| groupBy([aid, DomainName], limit=max)
| table([aid, DomainName, _count], sortby=_count, limit=20, reverse=False)
```

It should also be noted that LogScale handles special character escaping with standard escaping. For example, if you wanted to enter the path \system32\config, you would write it and escape the backslashes like so:

```
"\\system32\\config\\"
```

By adding a timeframe, applying limits and filters, and escaping our searches properly, we can easily reduce the results list of our LogScale query to a useful, manageable amount of information. This decreases the time and complexity of hunting adversaries in your environment.

## ComputerName Lookups

Falcon LTR includes an FDR package in the Marketplace, which adds a collection of dashboards, saved queries, and scheduled searches. One such saved search generates us a lookup file called `fdr_aidmaster.csv`. This file contains the necessary information to lookup a `ComputerName` from an `aid`. When performing queries, it's best to utilize the `aid` field, and lookup the `ComputerName` when it's needed. For example the following query will collect all `ProcessRollup2` events from a user-provided `aid`, then add the `ComputerName` field by leveraging the lookup file `fdr_aidmaster.csv`.

```
#event_simpleName=ProcessRollup2 
| aid=?aid
| case {
    aid=* AND ComputerName!=*
      | match(file="fdr_aidmaster.csv", field=aid, include=ComputerName, ignoreCase=true, strict=true);
    * | default(field=ComputerName, value=NotMatched);
  }
```

The `case` statement in the query above can be copied and pasted as needed. It says "if there's an `aid` but not a `ComputerName`, then look up the `ComputerName` and set the value. Otherwise, assign it a default value of `NotMatched` if the `aid` isn't in the lookup file." This also prevents the `match` statement from overriding a `ComputerName` value if one already exists. 

In the event you are starting with a `ComputerName`, and need to lookup the `aid`, the `AgentOnline` event is your friend:

```
#event_simpleName=AgentOnline 
| ComputerName=?ComputerName
| head(5)
| select([@timestamp, aid, ComputerName, aip])
```

The above query returns the 5 most recent `AgentOnline` events which can be useful in the event you have multiple machines with the same hostname. For the purposes of this document, most queries will be executed by leveraging `aid`, and will exclude `ComputerName` lookups. For any query you'd like to add the lookup, add the following line:

```
...
| case {
    aid=* AND ComputerName!=*
      | match(file="fdr_aidmaster.csv", field=aid, include=ComputerName, ignoreCase=true, strict=true);
    * | default(field=ComputerName, value=NotMatched);
  }
```

Also make sure to add `ComputerName `to your output if leveraging something like `groupBy()`, `table()`, or `select()`.

## Change views

You can view the results of any event search query with one click. You can choose `Events Table` (default), `pie`, `bar`, or `scatter` charts, and even `Heat Map`, `Event List`, `Time Chart`, `Sankey`, `World Map`, and `Single Value`. For the purposes of hunting, we recommend using the `Table` view to view the raw data. This is also the only way you will be able to access workflows.

<img src=./images/views.png height=200>

## Filter out benign data

Hunting with Falcon is all about obtaining meaningful data. Thus, for every query you run, you will most likely want to filter out data that you know is unnecessary. Unnecessary data could be data that is irrelevant to what you are searching for or it could simply be data that you know is benign.

For example, let’s say you are hunting suspicious registry changes:

```
#event_simpleName=/Asep/ 
| aid=?aid
| groupBy([@timestamp, aid, RegObjectName], limit=max) 
| sort(@timestamp, order=asc, limit=1000)
```

We can make this more meaningful by filtering out a registry object that we know to be benign using the "does not equal" syntax (!=). This reduces the amount of results we get and speeds up the time it takes to run the query.

```
#event_simpleName=/Asep/ 
| aid=?aid RegObjectName!="VALUE" 
| groupBy([@timestamp, aid, RegObjectName], limit=max) 
| sort(timestamp, order=asc, limit=1000)
```

# Hunting queries

Show me any instances of common reconnaissance tools on a host:

```
#event_simpleName=ProcessRollup2 
| aid=?aid 
| ImageFileName=/(\/|\\)(?<FileName>\w*\.?\w*)$/
| FileName = /^(net|ipconfig|whoami|quser|ping|netstat|tasklist|hostname|at)\.exe$/i
| select([aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
```

Show me any instances where multiple recon commands were executed by the same parent process:

```
#event_simpleName=ProcessRollup2 
| aid=?aid 
| ImageFileName=/(\/|\\)(?<FileName>\w*\.?\w*)$/
| FileName = /^(net|ipconfig|whoami|quser|ping|netstat|tasklist|hostname|at)\.exe$/i
| groupBy([aid, ParentProcessId], function=[collect([UserName, ParentProcessId, ParentBaseFileName, FileName, CommandLine]), count(FileName, as="fname_count"), count(CommandLine, as="CLI_count")], limit=max)
| fname_count > 1 OR CLI_count > 1
```

Another version with clickable Process Explorer links and comments:

```
#event_simpleName=ProcessRollup2 
| aid=?aid
| ImageFileName=/(?<FileName>[^\\/|\\\\]*)$/
| FileName = /^(net|ipconfig|whoami|quser|ping|netstat|tasklist|hostname|at)\.exe$/i
| ProcessExplorer := format("[Process Explorer](https://falcon.crowdstrike.com/investigate/process-explorer/%s/%s)", field=["aid", "ParentProcessId"])
| groupBy([aid, ParentProcessId], function=[collect([UserName, ParentProcessId, ParentBaseFileName, FileName, CommandLine, ProcessExplorer]), count(FileName, as="FileNameCount"), count(CommandLine, as="CommandLineCount")])
| FileNameCount > 1 OR CommandLineCount > 1
| drop([FileNameCount, CommandLineCount])
```

Show me any BITS transfers (can be used to transfer malicious binaries):

```
#event_simpleName=ProcessRollup2 
| ImageFileName=/\\bitsadmin\.exe/i CommandLine=/(Transfer|Addfile)/i
| join({#event_simpleName=UserIdentity | groupBy([aid, AuthenticationId, UserName], limit=max)}, field=AuthenticationId, include=UserName)
| groupBy([aid, CommandHistory], function=collect([UserName, CommandLine, ImageFileName, SHA256HashData]), limit=max)
```

Show me any powershell.exe downloads:

```
#event_simpleName=ProcessRollup2 
| ImageFileName=/\\powershell\.exe/i CommandLine=/(Invoke-WebRequests|Net\.WebClient|Start-BitsTransfer)/i
| join({#event_simpleName=UserIdentity | groupBy([aid, AuthenticationId, UserName], limit=max)}, field=AuthenticationId, include=UserName)
| select([aid, UserName, ImageFileName, CommandLine])
```

Show me any encoded PowerShell commands:

```
#event_simpleName=ProcessRollup2 
| ImageFileName=/\\powershell\.exe/i CommandLine=/\s-[e^]{1,2}[ncodema^]+\s/i
| join({#event_simpleName=UserIdentity | groupBy([aid, AuthenticationId, UserName], limit=max)}, field=AuthenticationId, include=UserName)
| select([aid, UserName, ImageFileName, CommandLine])
```

Show me a list of processes that executed from the Recycle Bin:

```
#event_simpleName=ProcessRollup2 
| aid=?aid ImageFileName=/\$Recycle\.Bin/i
| groupBy(aid, function=collect([SHA256HashData, ImageFileName]), limit=max)
```

Processes generally shouldn’t be executing from user spaces. These paths cover spaces that are considered to be User Paths. Show me a list of processes executing from User Profile file paths:

```
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| ImageFileName=/(\\Desktop\\|\\AppData\\)/
| join({#event_simpleName=UserIdentity | groupBy([aid, AuthenticationId, UserName], limit=max)}, field=AuthenticationId, include=UserName)
| select([aid, UserName, ImageFileName, SHA256HashData]) 
```

Show me a list of processes executing from browser file paths. Similar to the previous query, processes typically shouldn’t be running from these locations:

```
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
ImageFileName=/(\\AppData\\Local\\Microsoft\\Windows\\Temporary.Internet.Files\\[^\/|\\]*\.exe|.*\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\[^\/|\\]*\.exe|\\AppData\\Local\\Google\\Chrome\\[^\/|\\]*\.exe|\\Downloads\\[^\/|\\]*\.exe)/i
| aid=?aid 
| ImageFileName=/(?<FileName>[^\\/|\\\\]*)$/
| select([aid, ImageFileName, FileName, SHA256HashData])
```

Show me the responsible process for starting a service:

```
#event_simpleName=ProcessRollup2
| join({#event_simpleName=ServiceStarted}, key=RpcClientProcessId, field=SourceProcessId, include=ServiceDisplayName)
| select([aid, ImageFileName, ServiceDisplayName])
```

Show me binaries running as a service that do not originate from "System32":

```
#event_simpleName=ServiceStarted 
| ImageFileName!=/\\System32\\/i 
| select([aid, ServiceDisplayName, ImageFileName, CommandLine, ComputerName])
```

If hunting for anomalous activity, look for services that do not originate from "Windows\System32" location. Remember to escape the directory backslashes ("\") with another backslash.

The next query is similar to the previous query but more specific: this will look for "svchost.exe" running from unexpected locations, such as "C:\Windows\Temp". You can use any binary name or service of interest to find anomalous behavior. "ServiceDisplayName" can be substituted for "ImageFileName" if you want to hunt on service names instead. 

Show me an expected service running from an unexpected location:

```
#event_simpleName=ServiceStarted 
| ImageFileName=/\\svchost\.exe/i 
| ImageFileName!=/\\System32\\/i 
| case {
    aid=* AND ComputerName!=*
      | match(file="fdr_aidmaster.csv", field=aid, include=ComputerName, ignoreCase=true, strict=true);
    * | default(field=ComputerName, value=NotMatched);
  }
| select([aid, ComputerName, ServiceDisplayName, ImageFileName, CommandLine, ClientComputerName, RemoteAddressIP4, RemoteAddressIP6])
```

Certain malware and adversary tools might run as a service with specific names. To hunt for any of these services names, this query should allow for quick triage. 

Show me a specific service name:

```
#event_simpleName=ServiceStarted 
| ServiceDisplayName=?service
| case {
    aid=* AND ComputerName!=*
      | match(file="fdr_aidmaster.csv", field=aid, include=ComputerName, ignoreCase=true, strict=true);
    * | default(field=ComputerName, value=NotMatched);
  }
| select([aid, ComputerName, ServiceDisplayName, ImageFileName, CommandLine, ClientComputerName, RemoteAddressIP4, RemoteAddressIP6])
```

In the table fields, the `ContextTimeStamp` will provide the system time of event creation which will be useful when correlating with the time frame of interest. The `RemoteAddressIP4` will provide the IP address of the remote machine that initiated the request (origin) and `ClientComputerName` will provide the NetBios name of the remote machine.

The CreateService event has been updated in sensor version 2.27 to include the remote IP address (RemoteAddressIP4) as well as the hostname (ClientComputerName) of the machine that initiated the request. If the data is available, this query will show you the origin of the remote procedure call which could be useful in identifying compromised assets during an intrusion.

Show me all `CreateService` events:

```
#event_simpleName=CreateService
| case {
    aid=* AND ComputerName!=*
      | match(file="fdr_aidmaster.csv", field=aid, include=ComputerName, ignoreCase=true, strict=true);
    * | default(field=ComputerName, value=NotMatched);
  }
| select([aid, ComputerName, ServiceDisplayName, ServiceImagePath, ClientComputerName, RemoteAddressIP4, RemoteAddressIP6])
```

If hunting for anomalous activity, look for services that do not originate from "Windows\System32" location. Remember to escape the directory backslashes ("\") with another backslash.

Show me non-System32 binaries running as a hosted service:

```
#event_simpleName=HostedServiceStarted // ImageFileName!=/\\System32\\/i 
| case {
    aid=* AND ComputerName!=*
      | match(file="fdr_aidmaster.csv", field=aid, include=ComputerName, ignoreCase=true, strict=true);
    * | default(field=ComputerName, value=NotMatched);
  }
| select([aid, ServiceDisplayName, ImageFileName, ComputerName])
```

Show me a list of services that were stopped and on which hosts:

```
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| join({#event_simpleName=ServiceStopped}, key=TargetProcessId, field=TargetProcessId)
```

Use the next query to alert on when key services are stopped, such as Windows Firewall ("Base Filtering Engine") or other security related services.

```
#event_simpleName=HostedServiceStopped ServiceDisplayName=?service
| select([aid, ServiceDisplayName])
```

# Hunting phishing attacks and malicious attachments

Phishing is an attempt to acquire information such as user names, passwords, and credit card details by masquerading as a trustworthy entity in an electronic communication.

Show me a list of attachments sent from Outlook in the past hour that have a file name of "winword.exe", "excel.exe", or "powerpnt.exe":

```
#event_simpleName=ProcessRollup2 
| CommandLine=/content.outlook/i
| aid=?aid 
| ImageFileName=/(\/|\\)(?<FileName>\w*\.?\w*)$/
| FileName=/(winword|excel|powerpnt)\.exe/i
| CommandLine=/Outlook\\(?<ShortFile>\w*\\.*)$/i 
| select([@timestamp, aid, TargetProcessId, ShortFile, CommandLine])
```

Show me a list of links opened from Outlook in the last hour (Use Time Filter in UI):

```
#event_simpleName=ProcessRollup2 
| aid=?aid ImageFileName=/\\outlook\.exe/i
| regex("(?<FileName>[^\\/|\\\\]*)$", field=ImageFileName, strict=false)
| join(
    {
      #event_simpleName=ProcessRollup2 ImageFileName=/(chrome|firefox|iexplore)\.exe/i
      | MD5:=MD5HashData | ImageFileName=/(\/|\\)(?<ChildFileName>\w*\.?\w*)$/ 
      | ChildCLI:=CommandLine
    }, 
    key=ParentProcessId, field=TargetProcessId, include=[MD5, ChildFileName, ChildCLI]
  ) 
| groupBy([aid, FileName, CommandLine, ChildFileName, ChildCLI, MD5], limit=max)
```

# Hunting configuration and compliance vulnerabilities

A Local System account is an account that the operating system uses to run a lot of core functionality. As such, a Local System account has far more privileges than a typical user account. If a security adversary compromises a host running as Local System, they could leverage this configuration as an exploit and would not even need to obtain credentials. It’s important to ensure that every host running as Local System should in fact be running with this level of privilege.

Show me a list of web servers or database processes running under a Local System account:

```
#event_simpleName=ProcessRollup2
| ImageFileName=/(w3wp|sqlservr|httpd|nginx)\.exe/i
| groupBy(aid, function=collect([ImageFileName, CommandLine]), limit=max)
```

It might also be useful to audit account creations when hunting for anomalous activity. For example, if you observe administrator accounts created at 0300 local time, that could be a red flag depending on company change control policies.

Show me user accounts created with logon:

```
#event_simpleName=UserIdentity
| join({#event_simpleName=UserAccountCreated}, key=UserName, field=UserName)
```

Finally, it might be useful to audit account deletions when hunting for anomalous activity. Like account creations, if the account deletions are observed outside of normal change control times or if the account was recently created, it could be a red flag and an indication of the adversary covering their tracks.

Show me the responsible process for the `UserAccountCreated` event:

```
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| join({#event_simpleName=UserAccountCreated}, key=RpcClientProcessId, field=TargetProcessId, include=[UserName])
| select([aid, UserName, TargetProcessId, ImageFileName, CommandLine])
```

Older versions of common software can contain numerous vulnerabilities. You can search for hosts that are running older versions of software and mitigate the risk of having one of those vulnerabilities exploited. The following query will return the full file path of a specified piece of software which will indicate the software version.

Show me all versions of a certain piece of software that are running in my environment (such as Adobe Flash, Microsoft Word):

```
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2 OR #event_simpleName=ImageHash
| ImageFileName=/(\/|\\)(?<FileName>\w*\.?\w*)$/
| FileName=/SOFTWARE-NAME\.exe/i
| groupBy(ImageFileName, function=collect(aid), limit=max)
```

Example for Microsoft Word:

```
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2 OR #event_simpleName=ImageHash
| ImageFileName=/(\/|\\)(?<FileName>\w*\.?\w*)$/
| FileName=/winword\.exe/i
| groupBy(ImageFileName, function=collect(aid), limit=max)
```

# Hunting firewall anomalies and vulnerabilities

It could be useful to track firewall rules being added or modified in your environment, especially outside of normal change control hours. The following queries will show you which firewall rules were created and the process responsible. If you’re conducting an investigation on an endpoint where exfiltration of data is suspected, looking for recently added firewall rules might help triage on the adversary’s command and control infrastructure.

Show me all `FirewallSetRule` events:

```
#event_simpleName=FirewallSetRule
| select([aid, FirewallRule])
```

Show me all `FirewallSetRule` events grouped by host:

```
#event_simpleName=FirewallSetRule
| groupBy(aid, function=collect(FirewallRule), limit=max)
```

Rules set (with FirewallRule key/value extraction). The following query lists all rules created along with extracting out the key/value pairs from the FirewallRule attribute:

```
#event_simpleName=FirewallSetRule
| regex(field=FirewallRule, regex="App=(?<App>(.*?))\|", strict=false)
| regex(field=FirewallRule, regex="Active=(?<Active>(.*?))\|", strict=false)
| regex(field=FirewallRule, regex="Profile=(?<Profile>(.*?))\|", strict=false)
| regex(field=FirewallRule, regex="Protocol=(?<Protocol>(.*?))\|", strict=false)
| regex(field=FirewallRule, regex="Dir=(?<Dir>(.*?))\|", strict=false)
| regex(field=FirewallRule, regex="Desc=(?<Desc>(.*?))\|", strict=false)
| regex(field=FirewallRule, regex="Name=(?<Name>(.*?))\|", strict=false)
| select([aid, App, Name, Desc, Active, Dir, Profile])
```

Show me the responsible process:

```
#event_simpleName=ProcessRollup2
| join({#event_simpleName=FirewallSetRule}, key=ContextProcessId, field=TargetProcessId, include=[FirewallRule, FirewallRuleId])
| select([aid, FirewallRule, FirewallRuleId, ImageFileName, CommandLine])
```

It might also be useful to identify critical firewall rules in your environment and monitor them for deletion (especially outside of normal change control hours). These queries will show you which firewall rule was deleted and the process responsible.

Show me all `FirewallDeleteRule` events:

```
#event_simpleName=FirewallDeleteRule
| select([aid, FirewallRuleId])
```

Show me all `FirewallDeleteRule` events grouped by host:

```
#event_simpleName=FirewallDeleteRule
| groupBy(aid, function=collect(FirewallRuleId), limit=max)
```

Show me all responsible processes:

```
#event_simpleName=ProcessRollup2
| join({#event_simpleName=FirewallDeleteRule}, key=ContextProcessId, field=TargetProcessId, include=[FirewallRule, FirewallRuleId])
| select([aid, FirewallRuleId, ImageFileName, CommandLine])
```

The `FirewallChangeOption` event indicates that a firewall configuration option has been changed, such as enabling or disabling the firewall. The data will indicate the initial process (command-line tool, custom utility, or GUI application) or remote address/hostname that resulted in this action. It might be useful to see how often this occurs in your environment and by what process. Baselining allows for quicker triage on the edge cases where the activity is not expected.

Show me all `FirewallChangeOption` events (with human-readable profile description):

```
#event_simpleName=FirewallChangeOption
| FirewallProfile match {
    "0" => FirewallProfile := "Invalid" ;
    "1" => FirewallProfile := "Domain" ;
    "2" => FirewallProfile := "Standard" ;
    "3" => FirewallProfile := "Public" ;
    * => *}
| select([aid, FirewallOption, FirewallProfile, FirewallOptionNumericValue])
```

Show me the responsible process for the firewall change:

```
#event_simpleName=ProcessRollup2
| join({#event_simpleName=FirewallChangeOption}, key=ContextProcessId, field=TargetProcessId, include=[FirewallOption, FirewallProfile, FirewallOptionNumericValue])
| FirewallProfile match {
    "0" => FirewallProfile := "Invalid" ;
    "1" => FirewallProfile := "Domain" ;
    "2" => FirewallProfile := "Standard" ;
    "3" => FirewallProfile := "Public" ;
    * => * ;
  }
```

Show me the responsible process responsible for disabling firewall:

```
#event_simpleName=ProcessRollup2
| join({#event_simpleName=FirewallChangeOption FirewallOption=DisableFirewall}, key=ContextProcessId, field=TargetProcessId)
```

# Hunting suspicious network connections

After compromising a host, adversaries will often use FTP or another tool to transfer files and other data to an external host. You can use LogScale to hunt for those connections.

Show me a list of outbound network connections on a specific port:

```
#event_simpleName=NetworkConnect* 
| RemotePort=?RemotePort aid=?aid
| !cidr(RemoteAddressIP4, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32"])
| select([aid, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort])
```

Show me a list of infrequent connections on a specific port:

```
#event_simpleName=NetworkConnect* 
| RemotePort=?RemotePort aid=?aid
| groupBy(RemotePort, limit=max)
| sort(_count, order=asc, limit=1000)
```

Show me all networks connections to well-known remote ports, excluding ephemeral ports:

```
#event_simpleName=NetworkConnect* 
| RemotePort<=1023
| aid=?aid 
| groupBy(aid,function=collect(RemotePort), limit=max)
| sort(_count, limit=1000)
```

Domain names that are commonly looked up will receive many requests. You can hunt for low-volume domain name requests, because this might indicate anomalous behavior and, potentially, suspicious requests. Below is the base query and an example that shows how you should apply filtering to it.

Show me a list of low-volume domain name requests:

```
#event_simpleName=DnsRequest
| aid=?aid
| groupBy([aid, DomainName], limit=max)
| _count<4
```

For example, adding the following would remove all DomainName requests to the top level domain "google.com":

```
#event_simpleName=DnsRequest 
| DomainName!=*google.com aid=?aid 
| regex(regex=".*\..*", field=DomainName)
| groupBy([aid, DomainName], limit=max)
| _count <4
```

Typically, programs like Notepad and other operating system utilities will not be making network connections. Any such behavior could be suspicious. Given a process name, you can run this query to determine if a process is making network connections or DNS requests. 

Uncommon processes making network connections or DNS requests:

```
#event_simpleName=DnsRequest
| aid=?aid 
| join({#event_simpleName=ProcessRollup2 aid=?aid ImageFileName=/chrome\.exe/i}, key=TargetProcessId, field=ContextProcessId, include=[CommandLine, ImageFileName])
| select([@timestamp, aid, timestamp, DomainName, ImageFileName, CommandLine])
```

Example for Notepad:

```
#event_simpleName=DnsRequest
| aid=?aid
| join({#event_simpleName=ProcessRollup2 aid=?aid ImageFileName=/notepad\.exe/i}, key=TargetProcessId, field=ContextProcessId, include=[CommandLine, ImageFileName])
| select([@timestamp, aid, timestamp, DomainName, ImageFileName, CommandLine])
```

Uncommon processes making network connections to remote IP addresses on a specific host:

```
#event_simpleName=ProcessRollup2
| aid=?aid 
| join({#event_simpleName=NetworkConnectIP4 aid=?aid}, key=ContextProcessId, field=TargetProcessId, include=[RemoteAddressIP4])
| groupBy([aid, ImageFileName, RemoteAddressIP4], function=collect(CommandLine), limit=max)
```

Show all Remote Desktop Protocol (RDP) connections observed on a specific host:

```
#event_simpleName=UserIdentity
| aid=?aid LogonType=10
| select([@timestamp, UserName, UserPrincipal, LogonServer])
```

# Hunting anomalous behavior

Trusted processes are more likely to run dozens of times on a host. By searching for processes that ran only a few times, you can hunt for anomalous activity that might help spot malicious processes. Adversaries understand the need to avoid using highly visible processes, if they are to stay under the radar.

Show me processes that only ran a few of times on a specific host:

```
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| aid=?aid 
| groupBy([SHA256HashData, ImageFileName], limit=max)
| _count <5
| sort(_count, limit=1000)
```

It might be useful to audit account deletions when hunting for anomalous activity. Like account creations, if the account deletions are observed outside of normal change control times or if the account was recently created, it could be a red flag and an indication of the adversary covering their tracks.

Show me all deleted user accounts:

```
#event_simpleName=UserAccountDeleted
| aid=?aid 
| select([aid, UserName, UserRid])
```

When an adversary delivers a malicious file to a host, they’ll likely change or vary the file name so that it’s harder for analysts to find. This is a very common tactic used for phishing campaigns. Adversaries will use a different name for each file, but they will still follow some kind of a logical pattern, as the files are likely to be created programmatically. Thus, the file will not have the same name on each host, but we can nevertheless use an expression to hunt for them.

Hunt for a `CommandLine` query:

```
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| aid=?aid
| CommandLine=/YOURVALUEHERE/i 
| ImageFileName=/(\/|\\)(?<FileName>\w*\.?\w*)$/
| select([aid, FileName, ImageFileName, CommandLine])
```

The same with a `FileName` query:

```
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| aid=?aid 
| ImageFileName=/YOURVALUEHERE/i 
| ImageFileName=/(\/|\\)(?<FileName>\w*\.?\w*)$/
| select([aid, FileName, ImageFileName, CommandLine])
```

# Hunting anomalies related to scheduled tasks

The following two queries provide examples on how to work with the fields belonging directly to the event or extracting content from a scheduled task's XML content. These queries could be useful in hunting for anomalies within your network. Adversaries use “schtasks.exe” and “at.exe” to schedule the launch of their tools, malware (implants) and scripts on remote machines, which allows them to spread throughout your network and maintain persistence.

Show me `ScheduledTaskRegistered` events by host:

```
#event_simpleName=ScheduledTaskRegistered
| groupBy([aid, TaskName, TaskExecCommand, TaskAuthor], limit=max)
```

It might also be worthwhile to monitor scheduled tasks that are deleted outside of normal change windows based on your company's policies.

Show me `ScheduledTaskDeleted` events by host:

```
#event_simpleName=ScheduledTaskDeleted
| groupBy(aid, function=collect([TaskName, UserName]), limit=max)
```

Scheduled tasks can be configured to run under many conditions, including:

- At log on
- At startup
- At a specific time
- On a schedule
- On an event
- On idle

Show me events triggered at log on:

```
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger:=rename(Task.Triggers.LogonTrigger.Enabled)
| Trigger=* // Remove this line if you don't care if it's empty
| select([aid, Trigger, TaskXml])
```

Show me events triggered at startup:

```
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger:=rename(Task.Triggers.BootTrigger.Enabled)
| Trigger=* // Remove this line if you don't care if it's empty
| select([aid, Trigger, TaskXml])
```

Show me events triggered at a specific time:

```
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger:=rename(Task.Triggers.TimeTrigger.Enabled)
| Trigger=* // Remove this line if you don't care if it's empty
| select([aid, Trigger, TaskXml])
```

Show me events that are scheduled:

```
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger:=rename(Task.Triggers.CalendarTrigger.Enabled)
| Trigger=* // Remove this line if you don't care if it's empty
| select([aid, Trigger, TaskXml])
```

Show me events triggered on an event:

```
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger:=rename(Task.Triggers.EventTrigger.Enabled)
| Trigger=* // Remove this line if you don't care if it's empty
| select([aid, Trigger, TaskXml])
```

Show me tasks scheduled by logon type:

```
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| LogonType:=rename(Task.Principals.Principal.LogonType)
| LogonType=* // Remove this line if you don't care if it's empty
| select([aid, LogonType, TaskXml])
```

Show me tasks scheduled by user ID:

```
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| UserId:=rename(Task.Principals.Principal.UserId)
| select([aid, UserId, TaskXml])
```

Show me tasks scheduled by run level:

```
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| RunLevel:=rename(Task.Principals.Principal.RunLevel)
| RunLevel=* // Remove this line if you don't care if it's empty
| select([aid, RunLevel, TaskXml])
```

Show me tasks scheduled with ComHandler:

```
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| ComHandlerData:=rename(Task.Actions.ComHandler.Data)
| ComHandlerData=* // Remove this line if you don't care if it's empty
| select([aid, ComHandlerData, TaskXml])
```

Show me hidden scheduled tasks:

```
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Hidden:=rename(Task.Settings.Hidden)
| Hidden=/true/i
| select([aid, Hidden, TaskXml])
```

# Hunting suspicious registry changes

The Windows registry is a hierarchical database that stores the values of variables in Windows and the applications and services that run on Windows. The operating system and other programs also use the registry to store data about users and about the current configuration of the system and its components. Most end users never need to view or edit the registry. The administrative tools and Windows interface enable users to safely change their preferences and the services and features of the operating system. However, in rare instances, the only way to change an operating system variable is by editing the registry. Thus, because the registry contains sensitive, protected information about users and the host’s configuration, it is a common target of security adversaries.

```
#event_simpleName=/Asep/
| select([@timestamp, aid, RegObjectName]) 
| sort(@timestamp, order=desc, limit=1000)
```

# Hunting Java malware, trojans, and exploits

## Hunting Java malware and trojans

Show me DNS requests spawning from javaw.exe process (beaconing):

```
#event_simpleName=DnsRequest
| join({#event_simpleName=ProcessRollup2 ImageFileName=/javaw\.exe/i}, key=TargetProcessId, field=ContextProcessId, include=[CommandLine, ImageFileName])
| select([@timestamp, aid, timestamp, DomainName, ImageFileName, CommandLine])
```

Show me .JAR files written to %AppData%:

```
#event_simpleName=JarFileWritten 
| TargetFileName=/\\AppData\\/i
| select([aid, @timestamp, TargetFileName, SHA256HashData])
```

Show me .JAR files executed from %AppData%:

```
#event_simpleName=ProcessRollup2 
| ImageFileName=/javaw.exe/i CommandLine=/appdata/i
| select([aid, @timestamp, #event_simpleName, ImageFileName, SHA256HashData])
```

Show me ASEP for Java executables:

```
#event_simpleName=AsepValueUpdate 
| RegObjectName=/.*\\Run/i 
| RegValueName=/.*\.jar/i OR TargetFileName=/.*\.jar/i OR TargetCommandLineParameters=/.*\.jar/i
| case {
    aid=* AND ComputerName!=*
      | match(file="fdr_aidmaster.csv", field=aid, include=ComputerName, ignoreCase=true, strict=true);
    * | default(field=ComputerName, value=NotMatched);
  } 
| select([@timestamp, #event_simpleName, aid, ComputerName, ContextImageFileName, RegPostObjectName, RegObjectName, RegStringValue, RegValueName, TargetCommandLineParameters, TargetFileName])
| sort(@timestamp, order=desc, limit=1000)
```

## Hunting Java exploits

This query is used exclusively for portable executable files. Show me the Java.exe process writing executable files:

```
#event_simpleName=PeFileWritten
| join({#event_simpleName=ProcessRollup2 ImageFileName=/java\.exe/i}, key=TargetProcessId, field=ContextProcessId, include=[CommandLine, ImageFileName, Sha256HashData])
| case {
    aid=* AND ComputerName!=*
      | match(file="fdr_aidmaster.csv", field=aid, include=ComputerName, ignoreCase=true, strict=true);
    * | default(field=ComputerName, value=NotMatched);
  } 
| select([@timestamp, cid, aid, Customer, ComputerName, #event_simpleName, UserName, ImageFileName, CommandLine, TargetFileName, FileName, MD5HashData, SHA256HashData, CommandHistory])
```

This `NewExecutableWritten` event is generated when an executable file extension is written, whether or not it is truly an executable file type. Any file that ends with a known executable file extension (such as .exe, .bat, .scr) generates this event.

```
#event_simpleName=NewExecutableWritten
| join({#event_simpleName=ProcessRollup2 ImageFileName=/java\.exe/i}, key=TargetProcessId, field=ContextProcessId, include=[CommandLine, ImageFileName, Sha256HashData])
| select([@timestamp, cid, aid, Customer, #event_simpleName, ImageFileName, CommandLine, TargetFileName, FileName, MD5HashData, SHA256HashData, CommandHistory])
```

Hunt for child process of "whoami" spawning underneath Java.exe process. You can substitute "whoami" for any recon commands:

```
#event_simpleName=ProcessRollup2
| ImageFileName=/java\.exe/i
| join({#event_simpleName=CommandHistory ImageFileName=/whoami\.exe/i}, key=TargetProcessId, field=ParentProcessId, include=CommandHistory)
| select([@timestamp, cid, aid, Customer, #event_simpleName, ImageFileName, CommandLine, TargetFileName, FileName, MD5HashData, SHA256HashData, CommandHistory])
| sort(@timestamp, limit=1000)
```











