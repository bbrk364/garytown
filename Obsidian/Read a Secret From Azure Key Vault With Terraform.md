In this blog post, I will show you how to read a secret from an Azure Key Vault store using Terraform.

## Secret Store

In the last few articles, I have shown you how to [create](https://www.ntweekly.com/2021/01/28/deploy-an-azure-key-vault-with-terraform/) a secret store and add a [secret](https://www.ntweekly.com/2021/02/02/add-a-secret-to-azure-key-vault-with-terraform/) to it using Terraform with accessing the portal or Azure CLI \ PowerShell. Now it is time to learn how to read a secret from Azure Key Vault.

## Configuration

In the configuration below, I am first reading the information on my Azure Key Store and after outputting the secret in the following configuration.

data "azurerm_key_vault" "azvault" {
  name                = "myvault1"
  resource_group_name = "rgname"

}

data "azurerm_key_vault_secret" "secert" {
  name         = "secret-sauce"
  key_vault_id = data.azurerm_key_vault.azvault.id
}

output "secret_value" {
  value = data.azurerm_key_vault_secret.secret.value
}