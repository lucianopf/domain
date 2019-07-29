const aws = require('aws-sdk')
const { utils } = require('@serverless/core')

const getClients = (credentials, region) => {
  const route53 = new aws.Route53({
    credentials,
    region
  })

  const acm = new aws.ACM({
    credentials,
    region: 'us-east-1' // ACM must be in us-east-1
  })

  const cf = new aws.CloudFront({
    credentials,
    region
  })

  const apig = new aws.APIGateway({
    credentials,
    region
  })

  return {
    route53,
    acm,
    cf,
    apig
  }
}
const getDomains = (config) => {
  const domains = []

  for (const domain of config.dns || []) {
    const domainObj = {}
    if (domain.domain === 'root') {
      domainObj.domain = config.domain
    } else {
      domainObj.domain = `${domain.domain}.${config.domain}`
    }

    if (domain.target.url.includes('api')) {
      const id = domain.target.url.split('.')[0].split('//')[1]
      domainObj.id = id
      domainObj.type = 'api'
    }

    if (domain.target.url.includes('s3')) {
      domainObj.type = 's3'
    }

    domains.push(domainObj)
  }

  return domains
}

const getSecondLevelDomain = (domain) => {
  return domain
    .split('.')
    .slice(domain.split('.').length - 2)
    .join('.')
}

const getDomainHostedZoneId = async (route53, secondLevelDomain) => {
  const hostedZonesRes = await route53.listHostedZonesByName().promise()

  const hostedZone = hostedZonesRes.HostedZones.find(
    (zone) => zone.Name.includes(secondLevelDomain) // Name has a period at the end, which is why we're using includes rather than equals
  )

  if (!hostedZone) {
    throw Error(
      `Domain ${secondLevelDomain} was not found in your AWS account. Please purchase it from Route53 first then try again.`
    )
  }

  return hostedZone.Id.replace('/hostedzone/', '')
}

const createApigDomain = async (apig, route53, domain, certificateArn, domainHostedZoneId) => {
  const params = {
    domainName: domain,
    certificateArn: certificateArn,
    securityPolicy: 'TLS_1_2',
    endpointConfiguration: {
      types: ['EDGE']
    }
  }

  const apigDomainName = await apig.createDomainName(params).promise()

  const dnsRecord = {
    HostedZoneId: domainHostedZoneId,
    ChangeBatch: {
      Changes: [
        {
          Action: 'UPSERT',
          ResourceRecordSet: {
            Name: domain,
            Type: 'A',
            AliasTarget: {
              HostedZoneId: apigDomainName.distributionHostedZoneId,
              DNSName: apigDomainName.distributionDomainName,
              EvaluateTargetHealth: false
            }
          }
        }
      ]
    }
  }

  return route53.changeResourceRecordSets(dnsRecord).promise()
}

const deployS3Domain = async (route53, cf, domain, domainHostedZoneId, certificateArn) => {
  try {
    const params = {
      DistributionConfig: {
        CallerReference: String(Date.now()),
        Aliases: {
          Quantity: 2,
          Items: [domain, `www.${domain}`]
        },
        DefaultRootObject: 'index.html',
        Origins: {
          Quantity: 1,
          Items: [
            {
              Id: `S3-${domain}`,
              DomainName: `${domain}.s3.amazonaws.com`,
              OriginPath: '',
              CustomHeaders: {
                Quantity: 0,
                Items: []
              },
              S3OriginConfig: {
                OriginAccessIdentity: ''
              }
            }
          ]
        },
        OriginGroups: {
          Quantity: 0,
          Items: []
        },
        DefaultCacheBehavior: {
          TargetOriginId: `S3-${domain}`,
          ForwardedValues: {
            QueryString: false,
            Cookies: {
              Forward: 'none'
            },
            Headers: {
              Quantity: 0,
              Items: []
            },
            QueryStringCacheKeys: {
              Quantity: 0,
              Items: []
            }
          },
          TrustedSigners: {
            Enabled: false,
            Quantity: 0,
            Items: []
          },
          ViewerProtocolPolicy: 'redirect-to-https',
          MinTTL: 0,
          AllowedMethods: {
            Quantity: 2,
            Items: ['HEAD', 'GET'],
            CachedMethods: {
              Quantity: 2,
              Items: ['HEAD', 'GET']
            }
          },
          SmoothStreaming: false,
          DefaultTTL: 86400,
          MaxTTL: 31536000,
          Compress: false,
          LambdaFunctionAssociations: {
            Quantity: 0,
            Items: []
          },
          FieldLevelEncryptionId: ''
        },
        CacheBehaviors: {
          Quantity: 0,
          Items: []
        },
        CustomErrorResponses: {
          Quantity: 0,
          Items: []
        },
        Comment: '',
        Logging: {
          Enabled: false,
          IncludeCookies: false,
          Bucket: '',
          Prefix: ''
        },
        PriceClass: 'PriceClass_All',
        Enabled: true,
        ViewerCertificate: {
          ACMCertificateArn: certificateArn,
          SSLSupportMethod: 'sni-only',
          MinimumProtocolVersion: 'TLSv1.1_2016',
          Certificate: certificateArn,
          CertificateSource: 'acm'
        },
        Restrictions: {
          GeoRestriction: {
            RestrictionType: 'none',
            Quantity: 0,
            Items: []
          }
        },
        WebACLId: '',
        HttpVersion: 'http2',
        IsIPV6Enabled: true
      }
    }

    const res = await cf.createDistribution(params).promise()

    const distributionUrl = res.Distribution.DomainName

    const dnsRecordParams = {
      HostedZoneId: domainHostedZoneId,
      ChangeBatch: {
        Changes: [
          {
            Action: 'UPSERT',
            ResourceRecordSet: {
              Name: domain,
              Type: 'A',
              AliasTarget: {
                HostedZoneId: 'Z2FDTNDATAQYW2', // this is a constant that you can get from here https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
                DNSName: distributionUrl,
                EvaluateTargetHealth: false
              }
            }
          }
        ]
      }
    }

    await route53.changeResourceRecordSets(dnsRecordParams).promise()
  } catch (e) {
    if (e.code !== 'CNAMEAlreadyExists') {
      throw e
    }
  }
}

const deployApiDomain = async (
  apig,
  route53,
  domain,
  apiId,
  certificateArn,
  domainHostedZoneId
) => {
  try {
    await apig
      .createBasePathMapping({
        domainName: domain,
        restApiId: apiId,
        basePath: '(none)',
        stage: 'production'
      })
      .promise()
  } catch (e) {
    if (e.message === 'Invalid domain name identifier specified') {
      await createApigDomain(apig, route53, domain, certificateArn, domainHostedZoneId)

      // avoiding "too many requests error"
      await utils.sleep(1000)

      return deployApiDomain(apig, route53, domain, apiId, certificateArn, domainHostedZoneId)
    }

    if (e.message === 'Base path already exists for this domain name') {
      return
    }
    throw new Error(e)
  }
}

const createCertificate = async (acm, route53, secondLevelDomain, domainHostedZoneId) => {
  const params = {
    DomainName: secondLevelDomain,
    SubjectAlternativeNames: `*.${secondLevelDomain}`,
    ValidationMethod: 'DNS'
  }

  const certificate = await acm.requestCertificate(params).promise()

  const certificateDnsRecord = (await acm
    .describeCertificate({ CertificateArn: certificate.CertificateArn })
    .promise()).DomainValidationOptions.ResourceRecord

  const recordParams = {
    HostedZoneId: domainHostedZoneId,
    ChangeBatch: {
      Changes: [
        {
          Action: 'UPSERT',
          ResourceRecordSet: {
            Name: certificateDnsRecord.Name,
            Type: certificateDnsRecord.Type,
            ResourceRecords: [
              {
                Value: certificateDnsRecord.Value
              }
            ]
          }
        }
      ]
    }
  }

  await route53.changeResourceRecordSets(recordParams).promise()

  return certificate
}

const getCertificateArn = async (acm, route53, secondLevelDomain, domainHostedZoneId) => {
  const listRes = await acm
    .listCertificates({
      CertificateStatuses: ['ISSUED']
    })
    .promise()

  let certificate = listRes.CertificateSummaryList.find(
    (cert) => cert.DomainName === secondLevelDomain
  )

  if (!certificate) {
    certificate = await createCertificate(acm, route53, secondLevelDomain, domainHostedZoneId)
  }

  return certificate.CertificateArn
}

module.exports = {
  getClients,
  getDomains,
  getSecondLevelDomain,
  getDomainHostedZoneId,
  deployS3Domain,
  deployApiDomain,
  createCertificate,
  getCertificateArn
}
