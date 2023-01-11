:exclamation: The table of contents can be found by clicking on the 3-dot menu at the top-left of this document. :exclamation:

# Summary

This guide consists of function samples, and is meant to act as learning examples for the LogScale Query Language. 

The official LogScale documentation page can be found here:

https://library.humio.com/

# Function Examples

## Convert decimal value of Status to hex value

```
| Status_hex := format(field=Status, "%x")
```

## Exclude RFC1819 and non-routable IP addresses

```
| !cidr(LocalAddressIP4, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32"])
| !cidr(RemoteAddressIP4, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32"])
```

## Extract IP address from the field CommandLine

```
| regex("(?<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\:(?<port>\d{2,5})", field=CommandLine)
```

## Create link to Process Explorer in CrowdStrike Falcon

```
// Create Link to Process Explorer in Falcon (US-1)
| "Process Explorer" := format("[Process Explorer](https://falcon.crowdstrike.com/investigate/process-explorer/%s/%s)", field=["aid", "TargetProcessId"])

// Create Link to Process Explorer in Falcon (US-2)
| "Process Explorer" := format("[Process Explorer](https://falcon.us-2.crowdstrike.com/investigate/process-explorer/%s/%s)", field=["aid", "TargetProcessId"])

// Create Link to Process Explorer in Falcon (EU)
| "Process Explorer" := format("[Process Explorer](https://falcon.eu-1.crowdstrike.com/investigate/process-explorer/%s/%s)", field=["aid", "TargetProcessId"])

// Create Link to Process Explorer in Falcon (GOV)
| "Process Explorer" := format("[Process Explorer](https://falcon.laggar.gcw.crowdstrike.com/investigate/process-explorer/%s/%s)", field=["aid", "TargetProcessId"])
```

## Remove decimal place from timestamp field and convert to human-readable time

```
| PasswordLastSet := PasswordLastSet*1000
| PasswordLastSet := formatTime("%Y-%m-%d %H:%M:%S", field=PasswordLastSet, locale=en_US, timezone=Z)
```

## Get GeoIP data for the field aip

```
| ipLocation(field=aip)
```

## Match statement to replace UserIsAdmin decimal values with human-readable values

```
| UserIsAdmin match {
    1 => UserIsAdmin := "True" ;
    0 => UserIsAdmin := "False" ;
  }
```

## Replace the decimal value of UserIsAdmin with human-readable values

```
| replace(field=UserIsAdmin, regex="1", with="True")
| replace(field=UserIsAdmin, regex="0", with="False")
```

## Create shorthand process lineage in the field processLineage

```
| default(field=GrandParentBaseFileName, value="Unknown")
| format(format="%s > %s > %s", field=[GrandParentBaseFileName,  ParentBaseFileName, FileName], as="processLineage")
```

## Get GeoIP data for RDP user logins and place on world map with magnitude

```
#event_simpleName=UserLogon LogonType=10 RemoteAddressIP4=* 
| !cidr(RemoteAddressIP4, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32"])
| ipLocation(aip)
| worldMap(ip=aip, magnitude=count(aid))
```
