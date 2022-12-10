In Terraform Infrastructure as Code, Azure tags are a way to add metadata to the resources in Azure. Terraform configuration is an excellent opportunity for us to create tags and assign them to our resources. This blog post will discuss how we can do this using Terraform Configuration language with Terraform CLI commands.

## About Azure Tags

Azure resource tags are Azure management capabilities that allow you to quickly and easily identify Azure resources, such as Azure Virtual Machines (VMs), Azure Web Apps (WAs) and Azure SQL Data Warehouse (SQL DWs). Tags can help you organize your Azure resources into like or like-minded groups. The Azure portal lets you assign tags out of the box and lets you create custom tags.

The Azure Resource Manager (ARM) API provides a way for you to specify tags during creation time. You can also update tags for an existing resource that were created with terraform.

## Configuration

In the below configuration I am creating a log analytics workspace and using the _tags_ option to add two tags to the resource.

```
resource "azurerm_log_analytics_workspace" "TF" {
  name                = "loga-01"
  location            = azurerm_resource_group.TF.location
  resource_group_name = azurerm_resource_group.TF.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    env = "prod"
    costcentre = "corp"
  }
   
}
```