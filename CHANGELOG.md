## v0.0.4 - 2022-??-?? - Support the root

* Enable SUPPORTS_ROOT_NS for management of root NS records. Requires
  octodns>=0.9.16. Note that azure does not allow the removal of its own name
  servers so in cases where your config doesn't include them the provider will
  still leave them in place for azure.
* Include the version number in the __init__ output to ease reporting issues
  and more generally knowing what version you're working with.

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
