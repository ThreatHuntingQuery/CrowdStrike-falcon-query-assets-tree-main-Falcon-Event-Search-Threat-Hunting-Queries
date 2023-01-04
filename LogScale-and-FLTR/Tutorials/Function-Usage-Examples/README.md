# Summary <!-- omit from toc -->

These are examples of various functions in LogScale. The official LogScale documentation page can be found here:

https://library.humio.com/

# Table of Contents <!-- omit from toc -->

- [Convert decimal value of Status to hex value](#convert-decimal-value-of-status-to-hex-value)
- [Exclude RFC1819 and non-routable IP addresses](#exclude-rfc1819-and-non-routable-ip-addresses)
- [Extract IP address from the field CommandLine](#extract-ip-address-from-the-field-commandline)
- [Create link to Process Explorer in CrowdStrike Falcon](#create-link-to-process-explorer-in-crowdstrike-falcon)
- [Remove decimal place from timestamp field and convert to human-readable time](#remove-decimal-place-from-timestamp-field-and-convert-to-human-readable-time)
- [Get GeoIP data for the field aip](#get-geoip-data-for-the-field-aip)
- [Match statement to replace UserIsAdmin decimal values with human-readable values](#match-statement-to-replace-userisadmin-decimal-values-with-human-readable-values)
- [Replace the decimal value of UserIsAdmin with human-readable values](#replace-the-decimal-value-of-userisadmin-with-human-readable-values)
- [Create shorthand process lineage in the field processLineage](#create-shorthand-process-lineage-in-the-field-processlineage)
- [Get GeoIP data for RDP user logins and place on world map with magnitude](#get-geoip-data-for-rdp-user-logins-and-place-on-world-map-with-magnitude)

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