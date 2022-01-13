## AzureProvider provider for octoDNS

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
-e git+https://git@github.com/octodns/octodns_azure.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_azure
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
```

The first four variables above can be hidden in environment variables and octoDNS will automatically search for them in the shell. It is possible to also hard-code into the config file: eg, resource_group.

### Support Information

#### Records

AzureProvider supports A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, and TXT

#### Dynamic

AzureProvider has beta supports dynamic records.

Please read https://github.com/octodns/octodns/pull/706 for an overview of how dynamic records are designed and caveats of using them.

### Developement

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
