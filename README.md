# tfsecure
Policy driven unit and integration test Framework for Terraform

# Prerequisites
1. Generate a plan file for the terraform stack being used `terraform plan --out=plan.tfplan`
2. Create the policy files required for testing terraform resource, following is an example of such policy.
```{
    "resource_type": "aws_security_group",
    "rules": [
        {
            "property": "egress.cidr",
            "value": "0.0.0.0/0",
            "invert": true,
            "description": "egress should not be open to all"
        },
        {
            "property": "egress.protocol",
            "value": "tcp",
            "invert": false,
            "description": "egress protocol should be tcp"
        }

    ]

}
```
--> Currently each `resource_type` should have an individual json policy file.

# Usage
Usage of tfsecure:
  -policypath string
  Policy to be used for testing terraform plan
  -tfplanfile string
  Terraform generated plan file

tfsecure.go -tfplanfile=plan.tfplan -policypath=./policy
