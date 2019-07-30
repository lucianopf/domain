const { Component } = require('@serverless/core')
const {
  getClients,
  prepareDomains,
  getDomainHostedZoneId,
  describeCertificateByArn,
  getCertificateArnByDomain,
  createCertificate,
  validateCertificate,
  createCloudfrontDistribution,
  getCloudfrontDistribution,
  invalidateCloudfrontDistribution,
  deployApiDomain,
  removeAwsS3WebsiteResources,
} = require('./utils')

class Domain extends Component {

  /**
   * Remove
   */

  async default(inputs = {}) {
    this.context.status('Deploying')
    this.context.debug(`Starting Domain component deployment.`)

    this.context.debug(`Validating inputs.`)
    inputs.region = inputs.region || 'us-east-1'
    if (!inputs.domain) {
      throw Error(`"domain" is a required input.`)
    }

    // TODO: Check if domain has changed.
    // On domain change, call remove for all previous state.

    // Save domain
    this.state.domain = inputs.domain
    await this.save()

    // Get AWS SDK Clients
    const clients = getClients(this.context.credentials.aws)

    this.context.debug(`Formatting domains and identifying cloud services being used.`)
    const domains = prepareDomains(inputs)

    this.context.debug(`Getting the Hosted Zone ID for the domain ${inputs.domain}.`)
    const domainHostedZoneId = await getDomainHostedZoneId(clients.route53, inputs.domain)

    // Get AWS ACM Certificate by ARN
    this.context.debug(`Checking if an AWS ACM Certificate already exists.`)
    let certificate
    if (this.state.awsAcmCertificateArn) {
      try {
        certificate = await describeCertificateByArn(clients.acm, this.state.awsAcmCertificateArn)
        this.context.debug(`AWS ACM Certificate already exists.`)
      } catch(error) {
        if (error.code === 'ResourceNotFoundException') {
          this.context.debug(`Couldn't find Certificate based on ARN: ${this.state.awsAcmCertificateArn}.`)
        } else {
          throw new Error(error)
        }
      }
    }

    // Get AWS ACM Certificate by Domain or Create one
    if (!certificate) {
      this.context.debug(`Searching for an AWS ACM Certificate based on the domain: ${inputs.domain}.`)
      let certificateArn = await getCertificateArnByDomain(clients.acm, inputs.domain)
      if (!certificateArn) {
        this.context.debug(`No existing AWS ACM Certificates found for the domain: ${inputs.domain}.`)
        this.context.debug(`Creating a new AWS ACM Certificate for the domain: ${inputs.domain}.`)
        certificate = await createCertificate(clients.acm, inputs.domain)
      }
      certificate = await describeCertificateByArn(clients.acm, certificate.CertificateArn)
      this.state.awsAcmCertificateArn = certificate.CertificateArn
      await this.save()
    }

    this.context.debug(`Checking the status of AWS ACM Certificate.`)
    if (certificate.Status === 'PENDING_VALIDATION') {
      this.context.debug(`AWS ACM Certificate Validation Status is "PENDING_VALIDATION".`)
      this.context.debug(`Validating AWS ACM Certificate via Route53 "DNS" method.`)
      await validateCertificate(clients.acm, clients.route53, certificate, inputs.domain, domainHostedZoneId)
      this.context.log('Your AWS ACM Certificate has been created and is being validated via DNS.  This could take up to 30 minutes since it depends on DNS propagation.  Continuining deployment, but you may have to wait for DNS propagation.')
    }

    if (certificate.Status !== 'ISSUED' && certificate.Status !== 'PENDING_VALIDATION') {
      // TODO: Should we auto-create a new one in this scenario?
      throw new Error(`Your AWS ACM Certificate for the domain "${inputs.domain}" has an unsupported status of: "${certificate.Status}".  Please remove it manually and deploy again.`)
    }

    // Save dns info to state
    this.state.dns = this.state.dns && typeof this.state.dns === 'object' ? this.state.dns : {}

    // Setting up domains for different services
    for (const domainConfig of domains) {
      if (domainConfig.type === 'awsS3Website') {
        this.context.debug(`Configuring domain "${domainConfig.domain}" for S3 Bucket Website`)

        this.state.dns[domainConfig.domain] = this.state.dns[domainConfig.domain] || {}
        this.state.dns[domainConfig.domain].type = domainConfig.type

        let distribution
        let exists = false

        this.context.debug(`Checking existing AWS Cloudfront Distribution for "${domainConfig.domain}"`)
        if (this.state.dns[domainConfig.domain].awsCfDistributionArn) {
          try {
            distribution = await getCloudfrontDistribution(
              clients.cf,
              this.state.dns[domainConfig.domain].awsCfDistributionId
            )
            if (distribution) exists = true
          } catch(error) {
            this.context.debug(`Unable to find Distribution based on ARN "${this.state.dns[domainConfig.domain].awsCfDistributionArn}" due to error: "${error.message}"`)
          }
        }

        if (!distribution) {
          this.context.debug(`Creating new AWS Cloudfront Distribution for "${domainConfig.domain}"`)
          distribution = await createCloudfrontDistribution(
            clients.route53,
            clients.cf,
            domainConfig,
            domainHostedZoneId,
            certificate.CertificateArn
          )
          this.state.dns[domainConfig.domain].awsCfDistributionId = distribution.distributionId
          this.state.dns[domainConfig.domain].awsCfDistributionArn = distribution.distributionArn
          this.state.dns[domainConfig.domain].awsCfDistributionUrl = distribution.distributionUrl
          await this.save()
          this.context.debug(`Created new AWS Cloudfront Distribution for "${this.state.dns[domainConfig.domain].awsCfDistributionUrl}"`)
        }

        this.context.debug(`Using AWS Cloudfront Distribution with URL: "${domainConfig.domain}"`)

        // If distribution exists already, invalidate index.html file, so that the site reloads
        if (exists) {
          this.context.debug(`AWS Cloudfront Distribution already exists for "${domainConfig.domain}"`)
          this.context.debug(`Invalidating "index.html" of AWS Cloudfront Distribution for "${domainConfig.domain}".`)
          await invalidateCloudfrontDistribution(
            clients.cf,
            this.state.dns[domainConfig.domain].awsCfDistributionId
          )
        }

      } else if (domainConfig.type === 'awsApiGateway') {
        return deployApiDomain(
          clients.apig,
          clients.route53,
          domainConfig.domain,
          domainConfig.id,
          certificate.CertificateArn,
          domainHostedZoneId
        )
      }

      // TODO: Remove unused domains that are kept in state
    }

    const outputs = {}
    let hasRoot = false
    outputs.domains = domains.map((domainConfig) => {
      if (domainConfig.root) hasRoot = true
      return `https://${domainConfig.domain}`
    })

    if (hasRoot) outputs.domains.unshift(`https://www.${this.state.domain}`)

    return outputs
  }

  /**
   * Remove
   */

  async remove() {
    this.context.status('Deploying')
    this.context.debug(`Starting Domain component removal.`)

    // Get AWS SDK Clients
    const clients = getClients(this.context.credentials.aws)

    this.context.debug(`Getting the Hosted Zone ID for the domain ${this.state.domain}.`)
    const domainHostedZoneId = await getDomainHostedZoneId(
      clients.route53,
      this.state.domain
    )

    for (const domainState in this.state.dns) {

      if (domainState.type === 'awsS3Website') {
        await removeAwsS3WebsiteResources(
          clients.route53,
          clients.cf,
          domainHostedZoneId,
          this.state.dns[domainState].domain,
          this.state.dns[domainState].awsCfDistributionId,
          this.state.dns[domainState].awsCfDistributionUrl,
        )
      }
    }
  }
}

module.exports = Domain
