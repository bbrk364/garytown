This blog post will show you how to create two Linux Ubuntu Server 19.04 virtual machine on Microsoft Azure Terraform.

## Challenges

If you do a google search on creating more than one Linux VM with Terraform with Azure, you will get a lot of result without any clear understanding of how to do it.

This challenging task is the fact that each VM needs a dedicated Public IP address, NIC and a configuration that links all the configuration together. After researching the topic, I have come up with a working code that will create two Ubuntu VMs with a public IP address for each one.

This post builds on the code I have shown [here](https://www.ntweekly.com/2021/03/14/create-a-linux-virtual-machine-in-azure-with-terraform/) on how to create a single Linux VM on Azure with SSH keys.

## Configuration

The full code is shown below. The configuration will create a new resource group and will handle the end to end configuration. Make sure you create your [SSH](https://www.ntweekly.com/2021/03/11/how-to-use-ssh-keys-to-login-to-a-linux-host/) key before.

terraform {
   required_providers {
     azurerm = {
       source = "hashicorp/azurerm"
       version = "2.44.0"
     }
   }
 }

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 2.26"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "ubuntu" {
  name     = "ubuntu-resources"
  location = "australiaeast"
}

resource "azurerm_virtual_network" "ubuntu" {
  name                = "ubuntu-network"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.ubuntu.location
  resource_group_name = azurerm_resource_group.ubuntu.name
}

resource "azurerm_subnet" "ubuntu" {
  name                 = "internal"
  resource_group_name  = azurerm_resource_group.ubuntu.name
  virtual_network_name = azurerm_virtual_network.ubuntu.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_network_interface" "ubuntu" {
  count               = 2
  name                = "UBUNTU-NIC-${count.index}"
  location            = azurerm_resource_group.ubuntu.location
  resource_group_name = azurerm_resource_group.ubuntu.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.ubuntu.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = element(azurerm_public_ip.ubuntu.*.id, count.index)

  }
}

resource "azurerm_linux_virtual_machine" "ubuntu" {
  name                = "UBUNTU-VM-${count.index}"
  count               = 2
  resource_group_name = azurerm_resource_group.ubuntu.name
  location            = azurerm_resource_group.ubuntu.location
  size                = "Standard_ds1_v2"
  admin_username      = "adminuser"
  network_interface_ids = [
    element(azurerm_network_interface.ubuntu.*.id, count.index)
,
  ]
  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "19.04"
    version   = "latest"
  }

}

resource "azurerm_public_ip" "ubuntu" {
  count               = 2
  name                = "UBUNTU-VM-NIC-0${count.index}"
  resource_group_name = azurerm_resource_group.ubuntu.name
  location            = azurerm_resource_group.ubuntu.location
  allocation_method   = "Dynamic"

  tags = {
    environment = "Production"
  }
}

resource "azurerm_network_security_group" "ubuntu" {
  name                = "ubuntu-security-group1"
  location            = azurerm_resource_group.ubuntu.location
  resource_group_name = azurerm_resource_group.ubuntu.name

  security_rule {
    name                       = "ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    environment = "Production"
  }
}
resource "azurerm_network_interface_security_group_association" "ubuntu" {
    count = 2
    network_interface_id      = element(azurerm_network_interface.ubuntu.*.id, count.index)
    network_security_group_id = azurerm_network_security_group.ubuntu.id
}