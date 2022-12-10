This blog post will show you how to use zero time deployment with Terraform on Microsoft Azure and not have a single downtime between deployments.

By default, when we make changes to deployment in Terraform, Terraform will go ahead and destroy all the resources and recreate them. During the destroy and create you will have a downtime unless you use Zero time deployment.

## Zero Time Deployment

I know that the concept might sound complicated however in practice it is much simpler then it sounds.

In the example below, I have an Azure resource group that I have rename, and as a result, Terraform will delete the existing resource group. Using the lifecycle configuration block, I specify the option of create before destroy which will first, deploy the name resource group and only when it is up the old one will get deleted.

resource "azurerm_resource_group" "rg" {
  name     = "TRF123"
  location = "westus2"

  lifecycle {
    create_before_destroy = true
  }
}