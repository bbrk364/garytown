In this Terraform blog post, you will learn how to apply a Terraform configuration code with confirmation.

## Terraform Apply

When deploying a Terraform configuration using the _terraform apply_ command, we need to type _yes_ to confirm the deployment.

## Auto-Approve

To deploy a terraform configuration without confirmation, we use the _-auto-approve_ command switch as shown below.

```
terraform apply -auto-approve  
```