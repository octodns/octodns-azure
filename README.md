## Azure DNS & TrafficManager provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [Azure](https://azure.microsoft.com/en-us/services/dns/#overview).

### Installation

#### Command line

```
pip install octodns_azure
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns_azure==0.0.1
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
    # Current support of authentication of access to Azure services only
    # includes using a Service Principal:
    # https://docs.microsoft.com/en-us/azure/azure-resource-manager/
    #                        resource-group-create-service-principal-portal
    # The Azure Active Directory Application ID (aka client ID):
    client_id: env/AZURE_APPLICATION_ID
    # Authentication Key Value: (note this should be secret)
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
```

The first four variables above can be hidden in environment variables and octoDNS will automatically search for them in the shell. It is possible to also hard-code into the config file: eg, resource_group.

### Support Information

#### Records

AzureProvider supports A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, and TXT

#### Root NS Records

AzureProvider supports root NS record management, but Azure requires that its own name servers are present in the list. If your configured name servers does not include them the provider will still leave them in place to comply.

#### Dynamic

AzureProvider has beta supports dynamic records.

Please read https://github.com/octodns/octodns/pull/706 for an overview of how dynamic records are designed and caveats of using them.

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
        interval_in_seconds: 10
        timeout_in_seconds: 7
        tolerated_number_of_failures: 4
```

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
