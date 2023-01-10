:warning: These are unofficial packages. :warning:

These are unofficial packages used by the LogScale SE team during POVs. They are not meant to be a replacement for the official LogScale [Package Marketplace](https://library.humio.com/humio-server/packages-marketplace.html). However, feel free to use the content as necessary since they are meant to be learning examples. 

# Package Description

- Falcon telemetry [greenfield](./falcondata-greenfield) and [zen](./falcondata-zen) packages: these are functions, dashboards, queries, etc. This does not include a parser and is meant to be installed in a *view* of the Falcon telemetry data, *not* the repo. Both of these should be installed in the view since one is dependent on the other.
- Falcon telemetry [parser](./falcondate-parser): this is a standalone parser for Falcon telemetry based on the official `1.1.1` version of the FDR package. You likely do not need this for anything.