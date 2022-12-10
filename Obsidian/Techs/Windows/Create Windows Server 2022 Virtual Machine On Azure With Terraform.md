erraform is a tool for building, changing, and versioning infrastructure safely and efficiently. Terraform can be used to create new virtual machines on Azure that are running Windows Server 2022. This blog post will walk you through the process of deploying Windows Server 2022 on Azure.

## About Windows Server 2022

Windows Server 2022 is an operating system that provides new innovations to change how organizations work. Windows Server 2022 is a component of the cloud-ready solution stack that will deliver new capabilities for your enterprise. It includes an integrated, intelligent security framework that helps create a more secure environment for data and offers flexible deployment options with high availability. Deployment is simpler with the improved Windows Server Manager, dynamic provisioning, and simplified scaling.

## Configuration

Below is the end to end configuration. Make sure you set the username and password.

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
  name     = "WindowsServer2022"
  location = "australiaeast"
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
  size                = "Standard_D2_v4"
  admin_username      = "SETUSERNAME"
  admin_password      = "SETPASSWORD"
  network_interface_ids = [
    azurerm_network_interface.rg.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "microsoftwindowsserver"
    offer     = "windowsserver"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }

}
```