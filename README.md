## Azure DNS & TrafficManager provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [Azure](https://azure.microsoft.com/en-us/services/dns/#overview).

### Installation

#### Command line

```
pip install octodns-azure
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns-azure==0.0.1
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/octodns/octodns-azure.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_azure
```

### Configuration

```yaml
providers:
  azure:
    class: octodns_azure.AzureProvider
    # Current support of authentication of access to Azure services is
    # either using a Service Principal or deferring to an already authenticated
    # `az` CLI instance.
    # https://docs.microsoft.com/en-us/azure/azure-resource-manager/
    #                        resource-group-create-service-principal-portal
    # https://learn.microsoft.com/en-us/cli/azure/
    #
    # The authentication method, either 'client_secret' or 'cli'. This is
    # 'client_secret' by default
    client_credential_method: 'client_secret'
    # The Azure Active Directory Application ID (aka client ID). Required for
    # the 'client_secret' credential method.
    client_id: env/AZURE_APPLICATION_ID
    # Authentication Key Value: (note this should be secret). Required for the
    # 'client_secret' credential method
    key: env/AZURE_AUTHENTICATION_KEY
    # Directory ID (aka tenant ID):
    directory_id: env/AZURE_DIRECTORY_ID
    # Subscription ID:
    sub_id: env/AZURE_SUBSCRIPTION_ID
    # Resource Group name:
    resource_group: 'TestResource1'
    # All are required to authenticate.
    # Azure RetryPolicy Settings all of them are optional.
    # https://azuresdkdocs.blob.core.windows.net/$web/python/azure-core/1.9.0/azure.core.pipeline.policies.html?highlight=retrypolicy#azure.core.pipeline.policies.RetryPolicy
    # Total_retries default 10
    #client_total_retries: 10
    # status_retries default 3
    #client_status_retries: 3
    # The maximum number of record sets to return per page.
    # https://learn.microsoft.com/en-us/rest/api/dns/record-sets/list-by-dns-zone
    # Top default 100
    #top: 100
    # Azure AD authentication URL
    # defaults to: https://login.microsoftonline.com
    # docs: https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.clientsecretcredential?view=azure-python#parameters
    #authority: https://management.azure.com
    # ARM Management URL
    # defaults to: https://management.azure.com
    # docs: https://docs.microsoft.com/en-us/python/api/azure-mgmt-resource/azure.mgmt.resource.applicationclient?view=azure-python#parameters
    #base_url: https://management.azure.com
    # Manage Azure alias records that point at resources other than Traffic
    # Manager profiles, e.g. Front Door endpoints, as AzureProvider/ALIAS
    # records. See "Alias Records" below before enabling.
    # defaults to: false
    #manage_aliases: true
```

The variables starting with `env/` above can be hidden in environment variables and octoDNS will automatically search for them in the shell. It is possible to also hard-code into the config file: eg, resource_group.

For management of DNS zones on [Azure Private DNS](https://learn.microsoft.com/en-us/azure/dns/private-dns-overview), use `class: octodns_azure.AzurePrivateProvider`. Note that this provider does not support dynamic records or root NS records.

### Support Information

#### Records

AzureProvider supports A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, and TXT, as well as `AzureProvider/ALIAS` (see [Alias Records](#alias-records))

#### Root NS Records

AzureProvider supports root NS record management, but Azure requires that its own name servers are present in the list. If your configured name servers does not include them the provider will still leave them in place to comply.

#### Dynamic

AzureProvider has beta supports dynamic records.

Please read https://github.com/octodns/octodns/pull/706 for an overview of how dynamic records are designed and caveats of using them.

#### Alias Records

Azure [alias records](https://learn.microsoft.com/en-us/azure/dns/dns-alias) that point at a Traffic Manager profile are managed by octoDNS as dynamic records. Alias records that point at anything else, e.g. Front Door or CDN endpoints, public IP addresses, or other record sets in the zone, can be managed with the provider-specific `AzureProvider/ALIAS` record type once `manage_aliases: true` is set on the provider. octoDNS only manages the alias record sets, never the resources they point at.

```yaml
'':
  type: AzureProvider/ALIAS
  ttl: 300
  values:
    - type: A
      target-resource: /subscriptions/.../resourceGroups/rg/providers/Microsoft.Cdn/profiles/profile/afdEndpoints/endpoint
    - type: AAAA
      target-resource: /subscriptions/.../resourceGroups/rg/providers/Microsoft.Cdn/profiles/profile/afdEndpoints/endpoint
www:
  type: AzureProvider/ALIAS
  ttl: 300
  value:
    type: CNAME
    target-resource: /subscriptions/.../resourceGroups/rg/providers/Microsoft.Cdn/profiles/profile/afdEndpoints/endpoint
```

* Each value is a separate Azure alias record set of the given `type` (`A`, `AAAA`, or `CNAME`) at the record's name so a type can only appear once, `CNAME` can't be combined with other types, and it can't be used at the zone root. A name can't have both an `AzureProvider/ALIAS` value and a regular (or dynamic) record of the same type.
* `target-resource` is the Azure resource id of the target and is compared case-insensitively. Traffic Manager profiles aren't allowed, use dynamic records for those.
* Azure record sets each have their own TTL; if the alias record sets at a name differ the lowest is used and they'll all be updated to the configured `ttl` on the next sync.
* Switching a name between a regular/dynamic record and an alias replaces the Azure record set in place rather than deleting and re-creating it.
* When the target of an alias to another record set in the same zone is deleted Azure removes the alias as well.
* `AzureProvider/ALIAS` is only supported by `AzureProvider` (not `AzurePrivateProvider`). `YamlProvider` can store them, other providers treat them as an unsupported type. As with other provider-specific types the type is only registered when `octodns_azure` is loaded, i.e. when an Azure provider is part of the octoDNS config.

When `manage_aliases` is off (the default) such alias records are left alone: they're skipped, with a warning, when populating (including by `octodns-dump`), it's an error for the config to contain a record that would overwrite one, and it's an error for the config to contain `AzureProvider/ALIAS` records.

Enabling `manage_aliases` brings these alias records under octoDNS's management like any other record, meaning any that aren't in the config will be deleted. Before enabling it run `octodns-dump` against the provider with `manage_aliases: true` set and add the resulting `AzureProvider/ALIAS` records to your config. Migrating a lot of records from regular records to aliases (or vice versa) at once may trip the update/delete safety thresholds.

#### Healthchecks

AzureProvider supports the following healthcheck options for dynamic records (from [official documentation](https://docs.microsoft.com/en-us/azure/traffic-manager/traffic-manager-monitoring#configure-endpoint-monitoring)):

| Key | Description | Default |
|--|--|--|
| interval | This value specifies how often an endpoint is checked for its health from a Traffic Manager probing agent. You can specify two values here: 30 seconds (normal probing) and 10 seconds (fast probing). If no values are provided, the profile sets to a default value of 30 seconds. Visit the [Traffic Manager Pricing](https://azure.microsoft.com/pricing/details/traffic-manager) page to learn more about fast probing pricing. | 30 |
| timeout | This property specifies the amount of time the Traffic Manager probing agent should wait before considering a health probe check to an endpoint a failure. If the Probing Interval is set to 30 seconds, then you can set the Timeout value between 5 and 10 seconds. If no value is specified, it uses a default value of 10 seconds. If the Probing Interval is set to 10 seconds, then you can set the Timeout value between 5 and 9 seconds. If no Timeout value is specified, it uses a default value of 9 seconds. | 10 or 9 |
| num_failures | This value specifies how many failures a Traffic Manager probing agent tolerates before marking that endpoint as unhealthy. Its value can range between 0 and 9. A value of 0 means a single monitoring failure can cause that endpoint to be marked as unhealthy. If no value is specified, it uses the default value of 3. | 3 |

```
---
  octodns:
    azuredns:
      healthcheck:
        interval: 10
        timeout: 7
        num_failures: 4
```

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
