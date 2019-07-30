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
  deployApiDomain
} = require('./utils')

class Domain extends Component {

  /**
   * Remove
   */

  async default(inputs = {}) {
    this.context.status('Deploying')
    this.context.debug(`Starting Domain component.`)

    this.context.debug(`Validating inputs.`)
    inputs.region = inputs.region || 'us-east-1'
    if (!inputs.domain) {
      throw Error(`"domain" is a required input.`)
    }

    // Get AWS SDK Clients
    const clients = getClients(this.context.credentials.aws, inputs.region)

    this.context.debug(`Formatting domains and identifying cloud services being used.`)
    const domains = prepareDomains(inputs)

    this.context.debug(`Getting the Hosted Zone ID for the domain ${inputs.domain}.`)
    const domainHostedZoneId = await getDomainHostedZoneId(clients.route53, inputs.domain)

    // Get or Create an AWS ACM Certificate
    this.context.debug(`Checking if an AWS ACM Certificate already exists.`)
    let certificate
    if (this.state.awsAcmCertificateArn) {
      try {
        certificate = await describeCertificateByArn(clients.acm, this.state.awsAcmCertificateArn)
      } catch(error) {
        if (error.code === 'ResourceNotFoundException') {
          this.context.debug(`Couldn't find Certificate based on ARN: ${this.state.awsAcmCertificateArn}.`)
          this.context.debug(`Searching for an AWS ACM Certificate based on the domain: ${inputs.domain}.`)
          let certificateArn = await getCertificateArnByDomain(clients.acm, inputs.domain)
          if (certificateArn) {
            this.state.awsAcmCertificateArn = certificateArn
            await this.save()
            certificate = await describeCertificateByArn(clients.acm, this.state.awsAcmCertificateArn)
          } else {
            this.context.debug(`Couldn't find an AWS ACM Certificate based on the domain: ${inputs.domain}.`)
            this.context.debug(`Creating a new AWS ACM Certificate for the domain: ${inputs.domain}.`)
            certificate = await createCertificate(clients.acm, inputs.domain)
            this.state.awsAcmCertificateArn = certificate.CertificateArn
            await this.save()
            certificate = await describeCertificateByArn(clients.acm, this.state.awsAcmCertificateArn)
          }
        } else {
          throw new Error(error)
        }
      }
    }

    this.context.debug(`Checking the status of AWS ACM Certificate.`)
    if (certificate.Status === 'PENDING_VALIDATION') {
      this.context.debug(`AWS ACM Certificate Validation Status is "PENDING_VALIDATION".`)
      this.context.debug(`Validating AWS ACM Certificate via Route53 "DNS" method.`)
      await validateCertificate(clients.acm, clients.route53, certificate, inputs.domain, domainHostedZoneId)
      this.context.log('Your AWS ACM Certificate has been created and is being validated via DNS.  This could take up to 30 minutes since it depends on DNS propagation.  Continuining deployment, but you may have to wait for DNS propagation.')
    }

    if (certificate.Status !== 'ISSUED' && certificate.Status !== 'PENDING_VALIDATION') {
      // TODO: Should we delete the old one for the user or simply create a new one in this scenario?
      throw new Error(`Your AWS ACM Certificate for the domain "${inputs.domain}" has an unsupported status of: "${certificate.Status}".  Please remove it manually and deploy again.`)
    }

    // Save dns info to state
    this.state.dns = this.state.dns && typeof this.state.dns === 'object' ? this.state.dns : {}

    // Setting up domains for different services
    for (const domainConfig of domains) {
      if (domainConfig.type === 'awsS3') {
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
          this.context.debug(`Created new AWS Cloudfront Distribution for "${domainConfig.domain}"`)
        }

        // If distribution exists already, invalidate index.html file
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
  }

  /**
   * Remove
   */

  async remove() {}
}

module.exports = Domain
