# Domain

Easily provision custom domains for:

- Static websites hosted on AWS CloudFront & AWS S3 via the Website Component.
- APIs built via the Backend Component.

### Inputs

```yaml

domain:
  component: '@serverless/domain'
  inputs:
    privateZone: false
    domain: mywebsite.com
    subdomains:
      www: ${websiteComponentInstance}
      api: ${backendComponentInstance}
      admin: ${anotherWebsiteComponentInstance}

```

### Set-Up

First, you must purchase your domain within Route53 manually.  Then add it to the Component, as demonstrated above.

### Using With The Website Component

When used with the Website Component, the domain component will...

- Create an AWS ACM Certificate, if one does not already exists for the domain.
- Create an AWS Cloudfront Distribution that uses the AWS ACM Certificate.
- Create Records in AWS Route 53 to point your custom domain to your AWS Cloudfront Distribution.
