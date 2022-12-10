In this blog post, I will show you how to add a secret to Azure Key Vault using Terraform configuration.

Last week, I showed how to [create an Azure Key Vault using](https://www.ntweekly.com/2021/01/28/deploy-an-azure-key-vault-with-terraform/) Terraform that can be used to store secrets and certificates. Today we use an existing vault and create a secret using [Terraform](https://www.ntweekly.com/category/terraform).

## Configuration

In the following configuration, I am first using the Terraform data source configuration to get the details of my existing vault.

In the second configuration block, I am creating a secret and referring to the Key Vault ID using the data source configuration.

terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      version = "2.44.0"
    }
  }

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

data "azurerm_key_vault" "azvault" {
  name                = "vault1"
  resource_group_name = "myrg"  
}

resource "azurerm_key_vault_secret" "secret" {
  name         = "secretname"
  value        = "secretvalue"
  key_vault_id = data.azurerm_key_vault.azvault.id
}