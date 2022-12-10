In this post, we will focus on creating an App Service Plan (Linux or Windows) on Microsoft Azure with Terraform configuration.

## App Service Plan

Before we get to the actual code, let’s first review the purpose of an App Service Plan. In Microsoft Azure App Service Plan is the hosting plan that an App Service runs on. With an App Service Plan, we can’t run App Service on Azure.

An App Service can be a WordPress application, .Net app, Python, and more; however, the most fundamental component is the plan, and without it, we can run apps.

## Linux or Windows

Azure App Service Plan comes in two main flavours, Linux and Windows; the Linux plan runs on a Ubuntu server farm while the Windows plan runs on an IIS server; however, it is possible to run apps like WordPress on a Windows plans.

## Configuration

The following Terraform will create two App Service Plans. Linux and Windows. The SKU block section sets the size of the plan, and in the configuration below, I’m using P1V2 plans, which are production-ready.

If you only need a Linux or Windows, remove the code block of the one that you don’t need. The code was also tested on the Terraform 1.0 version and works well.

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


resource "azurerm_resource_group" "rg" {
  name     = "ntwtech"
  location = "westus2"
}

resource "azurerm_app_service_plan" "app-plan-linux" {
  name                = "ntweekly-linux"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  kind                = "Linux"
  reserved            = true

  sku {
    tier = "Standard"
    size = "p1v2"
  }
}

resource "azurerm_app_service_plan" "app-plan-win" {
  name                = "ntweekly-win"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  kind                = "windows"
  reserved            = false

  sku {
    tier = "Standard"
    size = "p1v2"
  }
}
```