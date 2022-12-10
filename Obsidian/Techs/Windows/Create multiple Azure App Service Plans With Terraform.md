This Terraform post will show you how to create multiple Azure App Service Plans (Linux or Windows).

In the previous post, we created a single App Service Plan, but this time we will take our learning one step up and create multiple and use variables and Terraform interpolation to create the App Service Plan names.

## App Service Plan

Azure App Service Plan is like a hosting plan that Web Apps (App Service) run inside them. They form compute and storage platforms for our applications.

## Configuration

In the following configuration, I’m creating two Azure App Service Plans. In the variable code block, I am setting the name of the plan. If you remove the default value, you will be prompt for a name.

In the App Service Plan block section, I am using interpolation to create the names of the plans. The format is deploycontainers-1.

```
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "2.41.0"
    }
  }
}

provider "azurerm"
  features  {}
}

variable app-service-plan-name {
  type        = string
  default     = "deploycontainers" 
  description = "Enter the name of the App Service plan"
}

resource "azurerm_resource_group" "rg" {
  name     = "ntwtech"
  location = "westus2"
}

resource "azurerm_app_service_plan" "app-plan-linux" {
  count = 2   
  name                = "${var.app-service-plan-name}-${count.index}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  kind                = "Linux"
  reserved            = true

  sku {
    tier = "Standard"
    size = "p1v2"
  }
}
```

To run the code, save it inside a folder with the .tf file extension and run the following commands.

```
terraform init
terraform plan
terraform apply
```

To delete and destory all the resource that this code has created run the followig command.

```
terraform destroy
```