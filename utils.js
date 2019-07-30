const aws = require('aws-sdk')
const { utils } = require('@serverless/core')

/**
 * Get Clients
 * - Gets AWS SDK clients to use within this Component
 */

const getClients = (credentials, region = 'us-east-1') => {
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

/**
 * Prepare Domains
 * - Formats component domains & identifies cloud services they're using.
 */

const prepareDomains = (config) => {
  const domains = []

  for (const subdomain in config.dns || []) {
    const domainObj = {}

    if (subdomain === '$') {
      domainObj.domain = config.domain
      domainObj.root = true
    } else {
      domainObj.domain = `${subdomain}.${config.domain}`
    }

    // Check if referenced Component is using AWS API Gateway...
    if (config.dns[subdomain].url.includes('execute-api')) {
      const id = domain.target.url.split('.')[0].split('//')[1]
      domainObj.id = id
      domainObj.type = 'awsApiGateway'
    }

    if (config.dns[subdomain].url.includes('s3')) {
      domainObj.type = 'awsS3Website'
      // Get S3 static hosting endpoint of existing bucket to use w/ CloudFront.
      // The bucket name must be DNS compliant.
      domainObj.s3BucketName = config.dns[subdomain].url.replace('http://', '').split('.')[0]
    }

    domains.push(domainObj)
  }

  return domains
}

/**
 * Get Domain Hosted Zone ID
 * - Every Domain on Route53 always has a Hosted Zone w/ 2 Record Sets.
 * - These Record Sets are: "Name Servers (NS)" & "Start of Authority (SOA)"
 * - These don't need to be created and SHOULD NOT be modified.
 */

const getDomainHostedZoneId = async (route53, domain) => {
  const hostedZonesRes = await route53.listHostedZonesByName().promise()

  const hostedZone = hostedZonesRes.HostedZones.find(
    // Name has a period at the end, so we're using includes rather than equals
    (zone) => zone.Name.includes(domain)
  )

  if (!hostedZone) {
    throw Error(
      `Domain ${domain} was not found in your AWS account. Please purchase it from Route53 first then try again.`
    )
  }

  return hostedZone.Id.replace('/hostedzone/', '')
}

/**
 * Describe Certificate By Arn
 * - Describe an AWS ACM Certificate by its ARN
 */

const describeCertificateByArn = async (acm, certificateArn) => {
  let certificate = await acm
    .describeCertificate({ CertificateArn: certificateArn })
    .promise()
  return certificate && certificate.Certificate ? certificate.Certificate : null
}

/**
 * Get Certificate Arn By Domain
 * - Gets an AWS ACM Certificate by a specified domain or return null
 */

const getCertificateArnByDomain = async (acm, domain) => {
  const listRes = await acm.listCertificates().promise()
  let certificate = listRes.CertificateSummaryList.find(
    (cert) => cert.DomainName === domain
  )
  return certificate && certificate.CertificateArn ? certificate.CertificateArn : null
}

/**
 * Create Certificate
 * - Creates an AWS ACM Certificate for the specified domain
 */

const createCertificate = async (acm, domain) => {

  const wildcardSubDomain = `*.${domain}`

  const params = {
    DomainName: domain,
    SubjectAlternativeNames: [ domain, wildcardSubDomain ],
    ValidationMethod: 'DNS'
  }

  return await acm.requestCertificate(params).promise()
}

/**
 * Validate Certificate
 * - Validate an AWS ACM Certificate via the "DNS" method
 */

const validateCertificate = async (acm, route53, certificate, domain, domainHostedZoneId) => {

   let readinessCheckCount = 10
   let validationResourceRecord

   /**
    * Check Readiness
    * - Newly Created AWS ACM Certificates may not yet have the info needed to validate it
    * - Specifically, the "ResourceRecord" object in the Domain Validation Options
    * - Ensure this exists.
    */

   const checkReadiness = async function () {

    if (readinessCheckCount < 1) {
      throw new Error('Your newly created AWS ACM Certificate is taking a while to initialize.  Please try running this component again in a few minutes.')
    }

    certificate = await describeCertificateByArn(acm, certificate.CertificateArn)

    // Find root domain validation option resource record
    certificate.DomainValidationOptions.forEach((option) => {
      if (domain === option.DomainName) {
        validationResourceRecord = option.ResourceRecord
      }
    })

    if (!validationResourceRecord) {
      readinessCheckCount--
      await utils.sleep(5000)
      return await checkReadiness()
    }
  }

  await checkReadiness()

  let checkRecordsParams = {
    HostedZoneId: domainHostedZoneId,
    MaxItems: '10',
    StartRecordName: validationResourceRecord.Name,
  }

  // Check if the validation resource record sets already exist.
  // This might be the case if the user is trying to deploy multiple times while validation is occurring.
  let existingRecords = await route53.listResourceRecordSets(checkRecordsParams).promise()

  if (!existingRecords.ResourceRecordSets.length) {
    // Create CNAME record for DNS validation check
    // NOTE: It can take 30 minutes or longer for DNS propagation so validation can complete, just continue on and don't wait for this...
    const recordParams = {
      HostedZoneId: domainHostedZoneId,
      ChangeBatch: {
        Changes: [
          {
            Action: 'UPSERT',
            ResourceRecordSet: {
              Name: validationResourceRecord.Name,
              Type: validationResourceRecord.Type,
              TTL: 300,
              ResourceRecords: [
                {
                  Value: validationResourceRecord.Value
                }
              ]
            }
          }
        ]
      }
    }
    await route53.changeResourceRecordSets(recordParams).promise()
  }
}

/**
 * Create AWS API Gateway Domain
 */

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

/**
 * Deploy AWS API Gateway Domain
 */

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

/**
 * Get CloudFront Distribution
 */

const getCloudfrontDistribution = async (cf, distributionId) => {
  const params = {
    Id: distributionId
  }
  let distribution = await cf.getDistribution(params).promise()
  return distribution
}

/**
 * Create Cloudfront Distribution
 */

const createCloudfrontDistribution = async (route53, cf, domainConfig, domainHostedZoneId, certificateArn) => {
  try {
    const params = {
      DistributionConfig: {
        CallerReference: String(Date.now()),
        Aliases: {
          Quantity: 1,
          Items: [ domainConfig.domain ]
        },
        DefaultRootObject: 'index.html',
        Origins: {
          Quantity: 1,
          Items: [
            {
              Id: `S3-${domainConfig.s3BucketName}`,
              DomainName: `${domainConfig.s3BucketName}.s3.amazonaws.com`,
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
          TargetOriginId: `S3-${domainConfig.s3BucketName}`,
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

    let res = await cf.createDistribution(params).promise()
    res = res.Distribution

    const distributionId = res.Id
    const distributionArn = res.ARN
    const distributionUrl = res.DomainName

    const dnsRecordParams = {
      HostedZoneId: domainHostedZoneId,
      ChangeBatch: {
        Changes: [
          {
            Action: 'UPSERT',
            ResourceRecordSet: {
              Name: domainConfig.domain,
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

    if (domainConfig.root) {
      dnsRecordParams.ChangeBatch.Changes.push({
        Action: 'UPSERT',
        ResourceRecordSet: {
          Name: `www.${domainConfig.domain}`,
          Type: 'A',
          AliasTarget: {
            HostedZoneId: 'Z2FDTNDATAQYW2', // this is a constant that you can get from here https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
            DNSName: distributionUrl,
            EvaluateTargetHealth: false
          }
        }
      })
    }

    await route53.changeResourceRecordSets(dnsRecordParams).promise()

    return {
      distributionId,
      distributionArn,
      distributionUrl,
    }

  } catch (e) {
    if (e.code !== 'CNAMEAlreadyExists') {
      throw e
    }
  }
}

/**
 * Invalidate Cloudfront Distribution
 */

const invalidateCloudfrontDistribution = async (cf, distributionId) => {
  const params = {
    DistributionId: distributionId,
    InvalidationBatch: {
      CallerReference: String(Date.now()),
      Paths: {
        Quantity: 1,
        Items: [
          '/index.html',
        ]
      }
    }
  }
  await cf.createInvalidation(params).promise()
}

/**
 * Remove AWS S3 Website Resources
 */

const removeAwsS3WebsiteResources = async (route53, cf, domainHostedZoneId, domain, distributionId, distributionUrl) => {

  const params = {
    HostedZoneId: domainHostedZoneId,
    ChangeBatch: {
      Changes: [
        {
          Action: 'DELETE',
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
  await route53.changeResourceRecordSets(params).promise()

}


/**
 * Exports
 */

module.exports = {
  getClients,
  prepareDomains,
  describeCertificateByArn,
  getCertificateArnByDomain,
  createCertificate,
  validateCertificate,
  getDomainHostedZoneId,
  createCloudfrontDistribution,
  getCloudfrontDistribution,
  invalidateCloudfrontDistribution,
  deployApiDomain,
  removeAwsS3WebsiteResources,
}
