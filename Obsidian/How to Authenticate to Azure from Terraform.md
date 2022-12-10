This post will show how to authenticate to Microsoft Azure from Terraform and deploy resources.

Authentication to Microsoft Azure is an essential requirement for deploying resources with Terraform. As of writing this post, Microsoft offers two authentication methods with Terraform.

1.  Using Azure CLI (Azure PowerShell is not supported)
2.  Using a Service Principal Account and environment variables.

Today we will cover the first option, Using Azure CLI.

## Install Azure CLI

You must first install Azure CLI on Windows, Linux, or macOS to get started.

Once Azure CLI is installed, log in using the following command.

```
azure cli --use-device-code
```

Note – Using –use-device-code is handy when using a terminal.

After logging in to Azure, we need to set the subscription we would like to deploy resources. This command is needed if you have more than one Azure subscription in your tenant.

```
az account set --subscription "SUBSCRIPTION-NAME"
```

Once you are authenticated, you are ready to start using Terraform.