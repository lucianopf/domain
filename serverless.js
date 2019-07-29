const { Component } = require('@serverless/core')
const {
  getClients,
  getDomains,
  getDomainHostedZoneId,
  getCertificateArn,
  deployS3Domain,
  deployApiDomain
} = require('./utils')

class Domain extends Component {
  async default(inputs = {}) {
    this.context.status('Deploying')

    inputs.region = inputs.region || 'us-east-1'

    const domains = getDomains(inputs)
    const clients = getClients(this.context.credentials.aws, inputs.region)

    const domainHostedZoneId = await getDomainHostedZoneId(clients.route53, inputs.domain)
    const certificateArn = await getCertificateArn(
      clients.acm,
      clients.route53,
      inputs.domain,
      domainHostedZoneId
    )

    for (const domainConfig of domains) {
      if (domainConfig.type === 's3') {
        await deployS3Domain(
          clients.route53,
          clients.cf,
          domainConfig.domain,
          domainHostedZoneId,
          certificateArn
        )
      } else if (domainConfig.type === 'api') {
        return deployApiDomain(
          clients.apig,
          clients.route53,
          domainConfig.domain,
          domainConfig.id,
          certificateArn,
          domainHostedZoneId
        )
      }
    }
  }
  async remove() {}
}

module.exports = Domain
