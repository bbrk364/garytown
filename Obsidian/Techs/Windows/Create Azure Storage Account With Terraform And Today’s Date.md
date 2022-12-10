n this Terrafom blog post we will create an Azure Sstorage account and name it with today’s date using Terraform built in functions.

Yesterday we [learned](https://www.ntweekly.com/2021/06/23/use-built-in-functions-in-terraform-code-configuration/) how to use the built-in Terraform functions that come loaded with Terraform by default. Today we will build in that knowledge and use it to create a storage account that has today’s date.

In the following code, we use the built-in timestamp function that gives us today’s date and time. Then we are using another built-in function (formatdate) to format how we would like the date to look.

Since a storage account name in Azure has some naming restrictions we are formating the date to be in lowercase.

## Configuration

Below is the entire configuration, all you need to do is copy it and run it using the terraform plan and apply commands.

```
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "2.64.0"
    }
  }
}

provider "azurerm" {
  features  {}
}

locals {

 timest = timestamp()
 fulldate = formatdate( "DDMMMYYYYhhmmZZZ", local.timest )
 time = lower(local.fulldate)

}


output time {
    value = local.time 
}


resource "azurerm_resource_group" "rg" {
  name     = "tf-demo"
  location = "westus2"
}


resource "azurerm_storage_account" "rg" {
  name                     = local.time
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

}





```