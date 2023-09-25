## v0.0.6 - 2023-??-?? - ???

* Adds Provider.list_zones to enable new dynamic zone config functionality
* Newly added support for subnet targeting using the [Subnet traffic-routing method](https://learn.microsoft.com/en-us/azure/traffic-manager/traffic-manager-routing-methods#subnet)
  in Azure Traffic Managers.

## v0.0.5 - 2023-07-27 - More feature support

* Add support for [Azure Private DNS](https://learn.microsoft.com/en-us/azure/dns/private-dns-overview)
* Add support for `status=up` pool value flag (aka [Always Serve](https://azure.microsoft.com/en-us/updates/alwaysservega/))

## v0.0.4 - 2022-11-30 - Support the root

* Enable `SUPPORTS_ROOT_NS` for management of root NS records. Requires
  `octodns>=0.9.16`. Note that Azure does not allow the removal of its own name
  servers so in cases where your config doesn't include them the provider will
  still leave them in place for Azure.
* Bug fixes around usage of the default value also inside pools of dynamic
  records.

## v0.0.3 - 2022-03-04 - Honing requirements

* Fix traffic manager authentication with new azure-identity
* Improved pinning for azure python module version requirements

## v0.0.2 - 2022-01-23 - The required things

* Include msrestazure in install_requires to get a hidden dep covered

## v0.0.1 - 2022-01-04 - Moving

#### Nothworthy Changes

* Initial extraction of AzureProvider from octoDNS core

#### Stuff

Nothing
