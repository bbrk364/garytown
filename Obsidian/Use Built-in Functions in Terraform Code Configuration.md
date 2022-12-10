This Terraform post will show us how to use built-in function within a Terrafrom code configuration.

## Terraform Function

By default and out of the box [Terraform](https://www.ntweekly.com/category/terraform) comes with many built-in functions. The full list is located in the following Terraform [URL](https://www.terraform.io/docs/language/functions/index.html).

Using functions in our code is very handy; for example, using the date function, we can create object storage in Azure and name it using today’s date. This just one simple example, but there are many more.

## Configuration

In the example below, I’m using the built-in date function timestamp() to retrieve the date and time. After retriveving the date I’m formatting it using the formatdate() function and finally converting the date to lower cases.

In the last code block I’m printing out the results.

```
terraform { 
}

locals { 
 timest = timestamp()
 fulldate = formatdate( "DDMMMYYYYhhmmZZZ", local.timest )
 time = lower(local.fulldate)

}
output time {
    value = local.time 
}
```