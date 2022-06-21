variable "user" {}
variable "passwrod" {}
variable "region" {
  type        = string
  description = "AWS region"
  default     = "eu-west-1"
}
variable "default_tags" {
  type = map(string)

  default = {
    Terraform = "true"
  }
}