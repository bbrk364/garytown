Following our previous blog post on deploying Infrastructure as code (IAC) today, we will configure a Microsoft Azure Virtual machine to auto shutdown at a specific time every day.

## Auto Shutdown

The Azure Virtual Machine auto-shutdown feature allows us to automatically configure virtual machines to shut down every day at a specific time. This feature is essential when running test and development VMs and help reduce the costs.

The below code examples will configure auto-shutdown every day at 10 PM.

## Code

```
resource "azurerm_dev_test_global_vm_shutdown_schedule" "rg" {
  virtual_machine_id = azurerm_windows_virtual_machine.rg.id
  location           = azurerm_resource_group.rg.location
  enabled            = true

  daily_recurrence_time = "2200"
  timezone              = "AUS Eastern Standard Time"


  notification_settings {
    enabled         = false
   
  }
 }
```

Below is the entire code for setting up a [Windows Server 2022](https://www.ntweekly.com/2021/10/25/create-windows-server-2022-virtual-machine-on-azure-with-terraform/) VM with auto-shutdown.

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


resource "azurerm_dev_test_global_vm_shutdown_schedule" "rg" {
  virtual_machine_id = azurerm_windows_virtual_machine.rg.id
  location           = azurerm_resource_group.rg.location
  enabled            = true

  daily_recurrence_time = "2200"
  timezone              = "AUS Eastern Standard Time"


  notification_settings {
    enabled         = false
   
  }
 }

```