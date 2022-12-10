Azure Log Analytics Workspace is a solution for advanced log management. It provides insights into the logs collected. Azure Log Analytics Workspace is relevant to any organization with the scale of data processing or enterprise-level security requirements. It has features that help in monitoring, analyzing and detecting threats in various ways.

The workspace can be integrated with other systems like Azure Stream Analytics, which will increase the speed of handling even more complex queries. With this integration, organizations can avoid lag in their system response time due to heavy data analytics demands.

## Terraform for Microsoft Azure

Before you start with Terraform on Azure, make sure you have Terraform [installed](https://www.ntweekly.com/2021/01/06/install-terraform-on-ubuntu-with-auto-complete/) and [Azure CLI](https://www.ntweekly.com/2018/05/06/use-azure-cli-2-0/) installed on your machine. Terraform uses Azure CLI for authentication.

## TF Configuration

In the below TF configuration file, we are creating a Log Analytics Workspace with 30 days retention period (the range is between 30-730) in the East US region and tagging the resource with two tags.

```
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 2.26"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "TF" {
  name     = "TF-LOGs"
  location = "eastus"
}

resource "azurerm_log_analytics_workspace" "TF" {
  name                = "loga-01"
  location            = azurerm_resource_group.TF.location
  resource_group_name = azurerm_resource_group.TF.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    env = "prod"
    costcentre = "corp"
  }
   
}
```

As always, to run the configuration, use these commands.

```
terraform init
terrafrom plan
terraform deploy
```

For more articles about Azure and Terraform visit the links below.