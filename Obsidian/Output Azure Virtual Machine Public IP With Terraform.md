When deploying Windows or Linux Virtual Machines to Microsoft Azure, we could use Terraform to output the VM IP address.

This post will show how to output the public IP address of a deployed Azure VM.

## Terraform Output

The following code will output the public IP of a Microsoft Azure virtual machine after the deployment is completed.

```
 output "VM-IP" {
     description = "The VM Public IP is:"
     value = azurerm_public_ip.vm1publicip.ip_address
 }    
```

To use the code, change the _vm1publicip_ to the name of your public IP address. Copy the code either in your main .tf file or your _outputs.tf_ file.