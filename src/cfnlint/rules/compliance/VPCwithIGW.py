"""
  Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Permission is hereby granted, free of charge, to any person obtaining a copy of this
  software and associated documentation files (the "Software"), to deal in the Software
  without restriction, including without limitation the rights to use, copy, modify,
  merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
  PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
  HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
from cfnlint import CloudFormationLintRule
from cfnlint import RuleMatch


class VPCwithIGW(CloudFormationLintRule):
    """Check whether a VPC has an IGW attached"""
    id = 'C1001'
    shortdesc = 'Compliance: No IGW in any VPC'
    description = 'Rule NIST 800-53 item 123.456.789'
    source_url = 'https://github.com/aws-cloudformation/cfn-python-lint'
    tags = ['compliance', 'igw']

    required_keys = [
        'Resources'
    ]

    def match(self, cfn):
        """Check gateway attachments"""
        matches = []

        gwas = cfn.get_resources('AWS::EC2::VPCGatewayAttachment')

        for gwa_name, gwa_values in gwas.items():
            properties = gwa_values.get('Properties')
            if properties:
                vpc_id = properties.get('VpcId').get('Ref')
                if vpc_id:
                    vpcs = cfn.get_resources('AWS::EC2::VPC')
                    for vpc_name, vpc_values in vpcs.items():
                        vpc_properties = vpc_values.get('Properties')
                        if vpc_properties:
                            cidr_block = vpc_properties.get('CidrBlock')
                            if cidr_block:
                                path = ['Resources', vpc_name]
                                message = 'Found VPC {0} with CidrBlock {1} with a prohibited InternetGatewayAttachment {2}'
                                matches.append(RuleMatch(path, message.format(vpc_name,cidr_block,gwa_name)))
                
        return matches
