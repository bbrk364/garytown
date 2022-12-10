his blog post will show you how to create a Bastion host on Microsoft Azure using Terraform configuration.

In the previous blog post, I have shown how to [create VNET, Subnet,](https://www.ntweekly.com/2022/06/23/create-azure-vnet-subnet-and-nsg-with-terraform/) and an NSG using Terraform and today, we will add a Bastion host.

## Bastion Host

Azure Bastion hosts help us to protect Virtual machines by creating a management subnet that is only accessible using the Azure portal using a browser. A Bastion host can connect to Linux and Windows virtual machines.

## Terraform Configuration

The below Terraform configuration will create the following:

-   Resource Group
-   Network Security Group (NSG)
-   Virtual Network X2
-   Subnet (Server)
-   Bastion host

```
resource "azurerm_resource_group" "rg" {
  name     = "TF-LAN"
  location =  "westus"  
}

resource "azurerm_network_security_group" "nsg" {
  name                = "TF-LAN-NSG-1"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

}

resource "azurerm_virtual_network" "vnet-1" {
  name                = "TF-LAN-VNET-1"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = ["172.0.0.0/16"]
 
}

resource "azurerm_subnet" "server-subnet-1" {
  name                 = "internal"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet-1.name
  address_prefixes     = ["172.0.1.0/24"]
}

resource "azurerm_subnet" "bastionsubnet" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet-1.name
  address_prefixes     = ["172.0.2.224/27"]
}
```