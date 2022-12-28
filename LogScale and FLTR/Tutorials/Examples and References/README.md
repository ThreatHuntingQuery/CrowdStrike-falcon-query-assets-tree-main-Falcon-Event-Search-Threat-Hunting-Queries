# Summary

This document is written from a "How do I...?" perspective, e.g. wanting to add additional fields to a groupBy result. This document also assumes that you know the basics of the LogScale query language. 

# Examples

## Add a single field to groupBy results

Let's say you need to use `groupBy()` for aggregation, but also need to include fields such as the `aid`, `aip`, `event_simpleName`, etc. This is where the `stats()` and `collect()` functions come into play. 

Here's a simple example of adding `DomainName` to the results of grouping by `ComputerName` and `FileName`.  This says "group everything by unique pairs of `ComputerName` and `FileName`, and then collect all of the `DomainName` values from each of those unique pairings. 

```
groupBy([ComputerName, FileName], function=collect(DomainName))
```

The results look like this:

<img src=./images/image-2022-11-30_10-16-22.png width=200>

