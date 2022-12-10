Tags: 

In this blog post, we will deploy a Linux Ubuntu 20.04 EC2 instance on AWS as a Docker host using Terraform.

## Terraform

When it comes to providing service in AWS and Azure it is starting to be common to use a tool like Terraform to do the job and keep track of the deployment in code.

In this post, We will deeply the host using Terraform and complete the Docker installation using a Bash script that will install the latest stable release of Docker.

To read more about Terraform visit the [category](https://www.ntweekly.com/category/terraform) page on our sister blog _ntweekly.com._

Configuration

Below is our Terraform configuration code. If you look closely enough you will see that I’ve chosen a t2.medium size instance for the deployment. That instance has 2 vCPU and 4GB of ram.

I’m also using an SSH key to log in and not a password. The default user name to log in to Ubuntu is _ubuntu._

```
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "3.47.0"
    }
  }
}

provider "aws" {
  region = "ap-southeast-2"
}

variable "instance_names" {
    default = "deploycontainerhost01"
}



resource "aws_instance" "vm" {
  
  ami           = "ami-0567f647e75c7bc05"
  instance_type = "t2.medium"
  key_name = aws_key_pair.login.id

  tags = {
    Name = var.instance_names
  }
  
} 



resource "aws_key_pair" "login" {
  key_name   = "login"
  public_key = "ssh-rsa -- YOU public key here"
}

```

## Install Latest Stable Docker Version

After deploying the machine we need to install the latest Docker stable release using the official Docker installation script.

```
curl -fsSL https://get.docker.com -o get-docker.sh
./get-docker.sh
```