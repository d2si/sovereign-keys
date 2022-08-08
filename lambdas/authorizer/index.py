import re
import base64
import json
import os
import boto3
import logging

##########
# Logger #
##########
log_level = logging.INFO
# create logger
logger = logging.getLogger('apigateway')
logger.setLevel(log_level)
logger.propagate = False
# create console handler
ch = logging.StreamHandler()
ch.setLevel(log_level)
# create formatter
formatter = logging.Formatter('[%(asctime)s][%(threadName)s]%(levelname)s - %(message)s')
# add formatter to ch
ch.setFormatter(formatter)
# add ch to logger
logger.addHandler(ch)


##############
# Authorizer #
##############
authorized_vpc_table_name = os.environ['VPC_INFOS_TABLE']
logger.info(f'Creating Table resource on {authorized_vpc_table_name}...')
authorized_vpc_table = boto3.resource('dynamodb').Table(authorized_vpc_table_name)

sts = boto3.client('sts')

def get_ec2_resource(role_arn):
    assumed_role = sts.assume_role(
        RoleArn = role_arn,
        RoleSessionName = 'SovereignKeyApi',
        DurationSeconds = 900
    )
    return boto3.resource('ec2',
        aws_access_key_id = assumed_role['Credentials']['AccessKeyId'],
        aws_secret_access_key = assumed_role['Credentials']['SecretAccessKey'],
        aws_session_token = assumed_role['Credentials']['SessionToken']
    )

def lambda_handler(event, context):
    logger.info(json.dumps(event, default=str))

    # Collect context
    caller_vpc = event['requestContext']['identity']['vpcId']
    logger.info(f'Caller VPC: {caller_vpc}')
    caller_vpce = event['requestContext']['identity']['vpceId']
    logger.info(f'Caller VPC Endpoint: {caller_vpce}')
    caller_ip = event['requestContext']['identity']['sourceIp']
    logger.info(f'Caller IP address: {caller_ip}')

    # The pathParameter for the instance ID will only exist for calls related to instances
    caller_instance_id = event['pathParameters'].get('InstanceId')
    if caller_instance_id is not None:
        logger.info(f'Caller Instance ID: {caller_instance_id}')

    r = authorized_vpc_table.get_item(
        Key={
            'VPCID': caller_vpc
        },
        ProjectionExpression='RemoteRoleARN',
        ReturnConsumedCapacity='NONE'
    )

    # If the VPC is not in DynamoDB, the one calling us is not a customer or did not register properly
    if 'Item' not in r:
        raise Exception('Unauthorized')
    
    # If there is an instance ID in the path, we need to verify it
    if caller_instance_id is not None:
        # We got the role to assume, let's instanciate an EC2 resource to check things
        role_arn = r['Item']['RemoteRoleARN']
        logger.info(f'Found role: {role_arn}')
        ec2 = get_ec2_resource(role_arn)

        # Instance
        caller_instance = ec2.Instance(caller_instance_id)
        # If the instance does not have the expected IP or is not in the expected VPC, throw Exception
        try:
            caller_instance.load()
        except:
            raise Exception('Unauthorized')

        if caller_instance.private_ip_address != caller_ip or caller_instance.vpc_id != caller_vpc:
            raise Exception('Unauthorized')

    # At this point, we are satisfied that the instance calling us is who it pretend to be
    # So we start constructing our response to authorize the call
    tmp = event['methodArn'].split(':')
    apiGatewayArnTmp = tmp[5].split('/')
    awsAccountId = tmp[4]

    policy = AuthPolicy(caller_ip, awsAccountId)
    policy.restApiId = apiGatewayArnTmp[0]
    policy.region = tmp[3]
    policy.stage = apiGatewayArnTmp[1]
    # We authorize all calls
    policy.allowMethodWithConditions(HttpVerb.ALL, event['path'],
        {
            "IpAddress": {
                "aws:SourceIp": f'{caller_ip}/32'
            }
        }
    )

    # Finally, build the policy and return it
    authResponse = policy.build()
    logger.info(authResponse)
    return authResponse

class HttpVerb:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    PATCH = 'PATCH'
    HEAD = 'HEAD'
    DELETE = 'DELETE'
    OPTIONS = 'OPTIONS'
    ALL = '*'

class AuthPolicy:
    # The AWS account id the policy will be generated for. This is used to create the method ARNs.
    awsAccountId = ''
    # The principal used for the policy, this should be a unique identifier for the end user.
    principalId = ''
    # The policy version used for the evaluation. This should always be '2012-10-17'
    version = '2012-10-17'
    # The regular expression used to validate resource paths for the policy
    pathRegex = '^[/.a-zA-Z0-9-\*]+$'

    '''Internal lists of allowed and denied methods.

    These are lists of objects and each object has 2 properties: A resource
    ARN and a nullable conditions statement. The build method processes these
    lists and generates the approriate statements for the final policy.
    '''
    allowMethods = []
    denyMethods = []

    # The API Gateway API id. By default this is set to '*'
    restApiId = '*'
    # The region where the API is deployed. By default this is set to '*'
    region = '*'
    # The name of the stage used in the policy. By default this is set to '*'
    stage = '*'

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, condition):
        '''Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null.'''
        if verb != '*' and not hasattr(HttpVerb, verb):
            raise NameError('Invalid HTTP verb ' + verb + '. Allowed verbs in HttpVerb class')
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError('Invalid resource path: ' + resource + '. Path should match ' + self.pathRegex)

        if resource[:1] == '/':
            resource = resource[1:]

        resourceArn = 'arn:aws:execute-api:{}:{}:{}/{}/{}/{}'.format(self.region, self.awsAccountId, self.restApiId, self.stage, verb, resource)

        if effect.lower() == 'allow':
            self.allowMethods.append({
                'resourceArn': resourceArn,
                'condition': condition
            })
        elif effect.lower() == 'deny':
            self.denyMethods.append({
                'resourceArn': resourceArn,
                'condition': condition
            })

    def _getEmptyStatement(self, effect):
        '''Returns an empty statement object prepopulated with the correct action and the
        desired effect.'''
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        '''This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy.'''
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['condition'] is None:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['condition']
                    statements.append(conditionalStatement)

            if statement['Resource']:
                statements.append(statement)

        return statements

    def allowAllMethods(self):
        '''Adds a '*' allow to the policy to authorize access to all methods of an API'''
        self._addMethod('Allow', HttpVerb.ALL, '*', None)

    def denyAllMethods(self):
        '''Adds a '*' allow to the policy to deny access to all methods of an API'''
        self._addMethod('Deny', HttpVerb.ALL, '*', None)

    def allowMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy'''
        self._addMethod('Allow', verb, resource, None)

    def denyMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy'''
        self._addMethod('Deny', verb, resource, None)

    def allowMethodWithConditions(self, verb, resource, condition):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Allow', verb, resource, condition)

    def denyMethodWithConditions(self, verb, resource, condition):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Deny', verb, resource, condition)

    def build(self):
        '''Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy.'''
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
                (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError('No statements defined for the policy')

        policy = {
            'principalId': self.principalId,
            'policyDocument': {
                'Version': self.version,
                'Statement': []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Allow', self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Deny', self.denyMethods))

        return policy
