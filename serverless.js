const { Component } = require('@serverless/core')
const {
  getClients,
  prepareSubdomains,
  getDomainHostedZoneId,
  describeCertificateByArn,
  getCertificateArnByDomain,
  createCertificate,
  validateCertificate,
  createCloudfrontDistribution,
  updateCloudfrontDistribution,
  getCloudFrontDistributionByDomain,
  invalidateCloudfrontDistribution,
  deployApiDomain,
  removeApiDomain,
  removeApiDomainDnsRecords,
  configureDnsForCloudFrontDistribution,
  getApiDomainName,
  removeWebsiteDomainDnsRecords
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
    inputs.privateZone = inputs.privateZone || false

    if (!inputs.domain) {
      throw Error(`"domain" is a required input.`)
    }

    // TODO: Check if domain has changed.
    // On domain change, call remove for all previous state.

    // Get AWS SDK Clients
    const clients = getClients(this.context.credentials.aws)

    this.context.debug(`Formatting domains and identifying cloud services being used.`)
    const subdomains = prepareSubdomains(inputs)
    this.state.region = inputs.region
    this.state.privateZone = inputs.privateZone
    this.state.domain = inputs.domain
    this.state.subdomains = subdomains
    await this.save()

    this.context.debug(`Getting the Hosted Zone ID for the domain ${inputs.domain}.`)
    const domainHostedZoneId = await getDomainHostedZoneId(
      clients.route53,
      inputs.domain,
      inputs.privateZone
    )

    this.context.debug(
      `Searching for an AWS ACM Certificate based on the domain: ${inputs.domain}.`
    )
    let certificateArn = await getCertificateArnByDomain(clients.acm, inputs.domain)
    if (!certificateArn) {
      this.context.debug(`No existing AWS ACM Certificates found for the domain: ${inputs.domain}.`)
      this.context.debug(`Creating a new AWS ACM Certificate for the domain: ${inputs.domain}.`)
      certificateArn = await createCertificate(clients.acm, inputs.domain)
    }

    this.context.debug(`Checking the status of AWS ACM Certificate.`)
    const certificate = await describeCertificateByArn(clients.acm, certificateArn)

    if (certificate.Status === 'PENDING_VALIDATION') {
      this.context.debug(`AWS ACM Certificate Validation Status is "PENDING_VALIDATION".`)
      this.context.debug(`Validating AWS ACM Certificate via Route53 "DNS" method.`)
      await validateCertificate(
        clients.acm,
        clients.route53,
        certificate,
        inputs.domain,
        domainHostedZoneId
      )
      this.context.log(
        'Your AWS ACM Certificate has been created and is being validated via DNS.  This could take up to 30 minutes since it depends on DNS propagation.  Continuining deployment, but you may have to wait for DNS propagation.'
      )
    }

    if (certificate.Status !== 'ISSUED' && certificate.Status !== 'PENDING_VALIDATION') {
      // TODO: Should we auto-create a new one in this scenario?
      throw new Error(
        `Your AWS ACM Certificate for the domain "${inputs.domain}" has an unsupported status of: "${certificate.Status}".  Please remove it manually and deploy again.`
      )
    }

    // Setting up domains for different services
    for (const subdomain of subdomains) {
      if (subdomain.type === 'awsS3Website') {
        this.context.debug(`Configuring domain "${subdomain.domain}" for S3 Bucket Website`)

        this.context.debug(`Checking CloudFront distribution for domain "${subdomain.domain}"`)
        let distribution = await getCloudFrontDistributionByDomain(clients.cf, subdomain.domain)
        if (!distribution) {
          this.context.debug(
            `CloudFront distribution for domain "${subdomain.domain}" not found. Creating...`
          )
          distribution = await createCloudfrontDistribution(
            clients.cf,
            subdomain,
            certificate.CertificateArn
          )
        } else if (
          !distribution.origins.includes(`${subdomain.s3BucketName}.s3.amazonaws.com`) ||
          !distribution.errorPages
        ) {
          this.context.debug(`Updating distribution "${distribution.url}".`)
          distribution = await updateCloudfrontDistribution(clients.cf, subdomain, distribution.id)
        }

        this.context.debug(`Configuring DNS for distribution "${distribution.url}".`)

        await configureDnsForCloudFrontDistribution(
          clients.route53,
          subdomain,
          domainHostedZoneId,
          distribution.url
        )

        this.context.debug(`Invalidating CloudFront distribution ${distribution.url}`)

        await invalidateCloudfrontDistribution(clients.cf, distribution.id)

        this.context.debug(`Using AWS Cloudfront Distribution with URL: "${subdomain.domain}"`)
      } else if (subdomain.type === 'awsApiGateway') {
        // Map APIG domain to API ID and recursively retry
        // if APIG domain need to be created first, or TooManyRequests error is thrown
        await deployApiDomain(
          clients.apig,
          clients.route53,
          subdomain,
          certificate.CertificateArn,
          domainHostedZoneId,
          this // passing instance for helpful logs during the process
        )
      }

      // TODO: Remove unused domains that are kept in state
    }

    const outputs = {}
    let hasRoot = false
    outputs.domains = subdomains.map((subdomain) => {
      if (subdomain.domain.startsWith('www')) {
        hasRoot = true
      }
      return `https://${subdomain.domain}`
    })

    if (hasRoot) {
      outputs.domains.unshift(`https://${inputs.domain.replace('www.', '')}`)
    }
    return outputs
  }

  /**
   * Remove
   */

  async remove() {
    this.context.status('Deploying')

    if (!this.state.domain) {
      return
    }

    this.context.debug(`Starting Domain component removal.`)

    // Get AWS SDK Clients
    const clients = getClients(this.context.credentials.aws, this.state.region)

    this.context.debug(`Getting the Hosted Zone ID for the domain ${this.state.domain}.`)
    const domainHostedZoneId = await getDomainHostedZoneId(
      clients.route53,
      this.state.domain,
      this.state.privateZone
    )

    for (const subdomain in this.state.subdomains) {
      const domainState = this.state.subdomains[subdomain]
      if (domainState.type === 'awsS3Website') {
        this.context.debug(
          `Fetching CloudFront distribution info for removal for domain ${domainState.domain}.`
        )
        const distribution = await getCloudFrontDistributionByDomain(clients.cf, domainState.domain)

        if (distribution) {
          this.context.debug(`Removing DNS records for website domain ${domainState.domain}.`)
          await removeWebsiteDomainDnsRecords(
            clients.route53,
            domainState.domain,
            domainHostedZoneId,
            distribution.url
          )

          if (domainState.domain.startsWith('www')) {
            await removeWebsiteDomainDnsRecords(
              clients.route53,
              domainState.domain.replace('www.', ''), // it'll move on if it doesn't exist
              domainHostedZoneId,
              distribution.url
            )
          }
        }
      } else if (domainState.type === 'awsApiGateway') {
        this.context.debug(
          `Fetching API Gateway domain ${domainState.domain} information for removal.`
        )
        const domainRes = await getApiDomainName(clients.apig, domainState.domain)

        if (domainRes) {
          this.context.debug(`Removing API Gateway domain ${domainState.domain}.`)
          await removeApiDomain(clients.apig, domainState.domain)

          this.context.debug(`Removing DNS records for API Gateway domain ${domainState.domain}.`)
          await removeApiDomainDnsRecords(
            clients.route53,
            domainState.domain,
            domainHostedZoneId,
            domainRes.distributionHostedZoneId,
            domainRes.distributionDomainName
          )
        }
      }
    }
    this.state = {}
    await this.save()
    return {}
  }
}

module.exports = Domain
