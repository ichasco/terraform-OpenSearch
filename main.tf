#-------------------
## OPENSEARCH
#-------------------

resource "aws_opensearch_domain" "logs" {
  domain_name    = "logs"
  engine_version = "OpenSearch_1.2"

  cluster_config {
    instance_type          = "t3.medium.search"
    zone_awareness_enabled = false
    instance_count         = 2
    zone_awareness_config {
      availability_zone_count = 2
    }
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
    master_user_options {
      master_user_name     = var.username
      master_user_password = var.password
    }
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.logs.arn
    log_type                 = "ES_APPLICATION_LOGS"
  }

  vpc_options {
    subnet_ids         = [module.vpc.database_subnets[0]]
    security_group_ids = [aws_security_group.logs.id]
  }

  auto_tune_options {
    desired_state = "ENABLED"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 200
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.logs.arn
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    custom_endpoint_certificate_arn = aws_acm_certificate.private_global_domain.arn
    custom_endpoint_enabled         = true
    custom_endpoint                 = "logs.ichasco.com"
    enforce_https                   = true
    tls_security_policy             = "Policy-Min-TLS-1-2-2019-07"
  }

  tags = merge(
    var.default_tags,
    {
      Domain = "Logs",
    },
  )
}

resource "aws_opensearch_domain_saml_options" "logs" {
  domain_name = aws_opensearch_domain.logs.domain_name
  saml_options {
    enabled             = true
    roles_key           = "department"
    master_backend_role = "devops"
    idp {
      entity_id        = data.vault_generic_secret.logs.data["ENTITY_ID"]
      metadata_content = file(metadata.json)
    }
  }
}


#-------------------
## IAM
#-------------------

resource "aws_iam_service_linked_role" "logs" {
  aws_service_name = "opensearchservice.amazonaws.com"
}

resource "aws_opensearch_domain_policy" "logs" {
  domain_name     = aws_opensearch_domain.logs.domain_name
  access_policies = <<POLICIES
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "es:*",
      "Resource": "${aws_opensearch_domain.logs.arn}/*"
    }
  ]
}
POLICIES
}


#-------------------
## SECURITY GROUP
#-------------------

resource "aws_security_group" "logs" {
  description = "SG for OpenSearch instances"
  name        = "Logs OpenSearch"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"

    cidr_blocks = ["192.168.1.0/24"]
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"

    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }

  tags = merge(
    var.default_tags,
    {
      Name = "Logs OpenSearch",
    },
  )
}


#-------------------
## KMS
#-------------------

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "logs" {
  description             = "Logs OpenSearch"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  policy                  = <<EOF
{
  "Version" : "2012-10-17",
  "Id" : "key-default-1",
  "Statement" : [ {
      "Sid" : "Enable IAM User Permissions",
      "Effect" : "Allow",
      "Principal" : {
        "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
      "Action" : "kms:*",
      "Resource" : "*"
    },
    {
      "Effect": "Allow",
      "Principal": { "Service": "logs.${var.region}.amazonaws.com" },
      "Action": [ 
        "kms:Encrypt*",
        "kms:Decrypt*",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:Describe*"
      ],
      "Resource": "*"
    }
  ]
}
EOF

  tags = merge(
    var.default_tags,
    {
      Name = "Logs OpenSearch",
    },
  )
}

resource "aws_kms_alias" "logs" {
  target_key_id = aws_kms_key.logs.id
  name          = format("alias/%s", lower("Logs-OpenSearch"))
}


#------------------------
## DOMAIN / CERTIFICATE
#------------------------

data "aws_route53_zone" "private_global_domain" {
  provider = aws.root

  name = "ichasco.com."
}

resource "aws_acm_certificate" "private_global_domain" {
  domain_name       = "ichasco.com"
  validation_method = "DNS"

  subject_alternative_names = [
    "*.ichasco.com",
  ]

  tags = merge(
    var.default_tags,
    {
      Name = "Logs OpenSearch",
    },
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "private_global_domain" {
  provider = aws.root
  for_each = {
    for dvo in aws_acm_certificate.private_global_domain.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }
  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.private_global_domain.zone_id
}

data "aws_route53_zone" "private_global_domain_net" {
  name         = "ichasco.com."
  private_zone = true
}

resource "aws_route53_record" "logs" {
  zone_id = data.aws_route53_zone.private_global_domain_net.zone_id
  name    = "logs.ichasco.com"
  type    = "CNAME"
  ttl     = "300"
  records = [aws_opensearch_domain.logs.endpoint]
}


#-------------------
## CLOUDWATCH
#-------------------

resource "aws_cloudwatch_log_group" "logs" {
  name              = "OpenSearch-Logs"
  kms_key_id        = aws_kms_key.logs.arn
  retention_in_days = 30
}

resource "aws_cloudwatch_log_resource_policy" "logs" {
  policy_name = "opensearch logs"

  policy_document = <<CONFIG
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "es.amazonaws.com"
      },
      "Action": [
        "logs:PutLogEvents",
        "logs:PutLogEventsBatch",
        "logs:CreateLogStream"
      ],
      "Resource": "arn:aws:logs:*"
    }
  ]
}
CONFIG
}