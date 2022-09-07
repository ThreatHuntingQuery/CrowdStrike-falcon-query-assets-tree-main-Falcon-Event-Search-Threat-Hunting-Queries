Helpful lookup tables for Falcon Event Search

To view lookup table, example:

`| inputlookup aid_master.csv`

To merge data into query from lookup table, example:

`| lookup local=true aid_master aid OUTPUT Version, MachineDomain, AgentVersion`

```
aid_master.csv
aid_policy.csv
appinfo.csv
AsepClass.csv
AsepValue.csv
chassis.csv
cid_name.csv
cloud_instance_metadata.csv
cloud_instance_types.csv
cloud_providers.csv
cloud_regions.csv
detect_patterns.csv
LogonType.csv
managedassets.csv
patterndisposition.csv
ProductType.csv
unmanageable.csv
unmanaged.csv
userinfo.csv
usersid_username.csv
usersid_username_win.csv
version_osxversion.csv
win_status_codes.csv
```