In this blog post, we will upgrade a Terraform installation on Ubuntu Linux machine.

The process to upgrade [Terraform](https://www.ntweekly.com/category/terraform) is a bit different compared to other distributions. First, we need to find where Terraform is installed. We then remove the binary file and download a new one.

## Find Binary location

First, let’s find where the Terraform binary installation is located using the following command.

```
which terraform
```

The expected location is _/usr/local/bin_

Open the location and delete the Terraform binary using the following command.

```
sudo rm terraform
```

Now let’s download the latest Terraform binary using the following command. ( The latest version is located in _https://www.terraform.io/downloads.html_)

```
sudo wget sudo wget https://releases.hashicorp.com/terraform/1.0.6/terraform_1.0.6_linux_amd64.zip
```

## Unzip and Use

The last step will unzip the binary from the downloaded file and make Terraform available for use.

```
unzip terraform_1.0.6_linux_amd64.zip 
```

**Note:** To install the Terraform Autocomplete command helper run t_erraform -install-autocomplete_

At this stage, Terraform is ready, and we could check the version by using the command below.

```
terraform --version
```

The output is shown below.

```
Terraform v1.0.6
on linux_amd64
```

You can go ahead and delete the zip file.