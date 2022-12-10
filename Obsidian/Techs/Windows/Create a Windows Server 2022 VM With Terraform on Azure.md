This post will learn how to create a Windows Server 2022 virtual machine on Microsoft Azure with Terraform.

With the upcoming release of Windows Server 2022, Microsoft made the preview edition available on Azure and with Terraform to access it and deploy it using infrastructure-as-a-code.

Since the 2022 image is available in the [Azure](https://www.ntweekly.com/category/azure) marketplace and not as a normal image like Windows Server 2019, there is an extra step we need to follow before creating the VM.

## Extra Step

This step is documented in our previous [post](https://www.ntweekly.com/2021/06/27/azure-terraform-error-error-message-you-have-not-accepted-the-legal-terms-on-this-subscription/). Without getting into too many details of why it is needed you will need to run the following Terraform import command with your Azure tenant id.

```
terraform import azurerm_marketplace_agreement.microsoftwindowsserver /subscriptions/YOUR-AZURE-SUBSCRIPTION-ID/providers/Microsoft.MarketplaceOrdering/agreements/microsoftwindowsserver/offers/microsoftserveroperatingsystems-previews/plans/windows-server-2022
```

Once you run the above command, go ahead use the following configuration code to deploy the VM.

## Configuration

The following code will create a new resource group, networking (including a public IP), storage and login details. Make sure you set the username and password in lines 57 and 58. The code also includes accepting the legal agreement for the marketplace image, which is the second part of running the import command in the section above.

```
# Configure the Azure provider
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

resource "azurerm_resource_group" "rg" {
  name     = "Win-TF"
  location = "westus2"
}

resource "azurerm_marketplace_agreement" "microsoftwindowsserver" {
    publisher ="microsoftwindowsserver"
    offer     = "microsoftserveroperatingsystems-previews"
    plan       = "windows-server-2022"
   }

resource "azurerm_virtual_network" "rg" {
  name                = "rg-network"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "rg" {
  name                 = "internal"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.rg.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_network_interface" "rg" {
  name                = "rg-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.rg.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_windows_virtual_machine" "rg" {
  name                = "rg-machine"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_F2"
  admin_username      = "SETUSERNAME"
  admin_password      = "ENTERPASSWORD"
  network_interface_ids = [
    azurerm_network_interface.rg.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "microsoftwindowsserver"
    offer     = "microsoftserveroperatingsystems-previews"
    sku       = "windows-server-2022"
    version   = "latest"
  }
 
  plan{
    name  = "windows-server-2022"
    publisher ="microsoftwindowsserver"
    product = "microsoftserveroperatingsystems-previews"
  }
}

```