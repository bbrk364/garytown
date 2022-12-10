In this blog post, we will learn how to use a for-each statement to create multiple resources with Terraform and in the following example, we will use Azure.

## For-Each vs Count

In the previous [post](https://www.ntweekly.com/2021/06/21/create-multiple-azure-app-service-plans-with-terraform/), we learned how to create multiple Azure App Service Plans using the count option, which works well; however, the recommended way to create multiple resources is using a for-each statement.

## Configuration

In the following Terraform configuration, I declare a map of values called plans inside a local code block.

The plans map contain two key-value pairs with the names of the App Service Plans I would like to use. The keys are plan01 and plan02.

In the code block for the App Service Plan, I am using the for_each statement with the name of the value map. The last part of the code assigns the names using ${each.value}. From there the rest of the code is the same.

Using for-each is that it is a cleaner method to assign values than count and can scale better.

```
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "2.41.0"
    }
  }
}

provider "azurerm" {
  features  {}
}



locals{
  plans = {

    plan01 = "deploycontianers-linunx-1"
    plan02 = "deploycontianers-linunx-2"

  }
}

resource "azurerm_resource_group" "rg" {
  name     = "ntwtech"
  location = "westus2"
}

resource "azurerm_app_service_plan" "app-plan-linux" {
  for_each = local.plans
  name                = "${each.value}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  kind                = "Linux"
  reserved            = true

  sku {
    tier = "Standard"
    size = "p1v2"
  }
}
```