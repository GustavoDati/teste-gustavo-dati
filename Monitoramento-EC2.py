import boto3
from botocore.exceptions import ClientError
import json
import logging
import json
import urllib3

# Definição da classe SlackHandler
class SlackHandler(logging.Handler):
    def __init__(self, slack_webhook_url):
        super().__init__()
        self.slack_webhook_url = slack_webhook_url
        self.http = urllib3.PoolManager()

    def emit(self, record):
        # Filtra o log específico que não queremos enviar
        if "Found credentials in environment variables" in record.msg:
            return  # Ignora este log e não faz nada

        try:
            log_entry = self.format(record)
            slack_message = {
                "channel": "#monitoramento-cloud",
                "username": "Monitoramento Dati",
                "text": log_entry,
                "icon_emoji": ":rocket:"
            }
            encoded_message = json.dumps(slack_message).encode('utf-8')
            self.http.request('POST', self.slack_webhook_url,
                              body=encoded_message,
                              headers={'Content-Type': 'application/json'})
        except Exception as e:
            print(f"Erro ao emitir log para o Slack: {e}")

# Configuração do logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Instanciação e configuração do SlackHandler
slack_webhook_url = 'https://hooks.slack.com/services/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'  # Use sua URL de webhook real
slack_handler = SlackHandler(slack_webhook_url)
slack_handler.setLevel(logging.INFO)  # Define o nível de log que você deseja enviar para o Slack
logger.addHandler(slack_handler)

def assume_role(account_id, region):
    role_arn = f"arn:aws:iam::{account_id}:role/Dati-acc-access2"
    sts_client = boto3.client('sts', region_name=region)
    try:
        response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="LambdaSession")
        return response['Credentials']
    except ClientError as error:
        logging.error(f"Erro ao tentar assumir a role: {error}")
        return None

def is_instance_in_autoscaling_group(instance_id, autoscaling_client):
    try:
        response = autoscaling_client.describe_auto_scaling_instances(InstanceIds=[instance_id])
        return len(response['AutoScalingInstances']) > 0
    except ClientError as e:
        logging.error(f"Erro ao verificar grupo Auto Scaling da instância: {e}")
        return False

def get_all_ec2_instances(ec2_client, autoscaling_client):
    instances = []
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        page_iterator = paginator.paginate(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]
        )
        for page in page_iterator:
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    image_id = instance['ImageId']
                    image = ec2_client.describe_images(ImageIds=[image_id])

                    platform_description = image['Images'][0].get('Description', 'Plataforma da imagem não encontrada').lower() if image['Images'] else 'Plataforma da imagem não encontrada'
                    if 'amazon linux' in platform_description:
                        platform_name = 'Amazon Linux'
                    elif 'ubuntu' in platform_description:
                        platform_name = 'Ubuntu'
                    elif 'windows' in platform_description:
                        platform_name = 'Windows'
                    else:
                        platform_name = 'Other'

                    instance_info = {
                        'InstanceId': instance['InstanceId'],
                        'PlatformName': platform_name,
                        'ImageId': image_id,
                        'InstanceType': instance.get('InstanceType'),
                        'State': instance['State']['Name']
                    }

                    iam_instance_profile = instance.get('IamInstanceProfile')
                    if iam_instance_profile:
                        instance_info['InstanceProfileArn'] = iam_instance_profile['Arn']

                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            instance_info['Name'] = tag['Value']
                            break

                    if not is_instance_in_autoscaling_group(instance['InstanceId'], autoscaling_client):
                        instances.append(instance_info)
        return instances
    except ClientError as error:
        logging.error(f"Erro ao listar instâncias EC2: {error}")
        return []

def create_alarms_for_instance(instance_id, instance_name, cloudwatch_client,event,sns_topic_arn,credentials,instance_platform,instance_ami,instance_type):
    metrics = {
        'CPUUtilization': {'unit': '%', 'threshold': 80},
        'NetworkOut': {'unit': 'bytes', 'threshold': 1000000},
        'StatusCheckFailed_Instance': {'unit': 'boolean', 'threshold': 1},
        'StatusCheckFailed_System': {'unit': 'boolean', 'threshold': 1},
        'mem_used_percent':{'unit': '%', 'threshold': 80},
        'disk_used_percent':{'unit': '%', 'threshold': 80}
    }

    for metric, info in metrics.items():
        alarm_name = f"{instance_name or instance_id} {metric} Alarm"
        alarm_description = f"Alarme quando {metric} excede {info['threshold']}{info['unit']}"
        create_cloudwatch_alarm(
            instance_id=instance_id,
            instance_name=instance_name,
            metric_name=metric,
            threshold=info['threshold'],
            comparison_operator='GreaterThanThreshold' if info['unit'] != 'boolean' else 'GreaterThanOrEqualToThreshold',
            evaluation_periods=2,
            alarm_name=alarm_name,
            alarm_actions = sns_topic_arn,
            alarm_description=alarm_description,
            cloudwatch_client=cloudwatch_client,
            instance_platform = instance_platform,
            instance_ami = instance_ami,
            instance_type = instance_type

        )
        tag_cloudwatch_alarm(alarm_name,event,cloudwatch_client)

def create_cloudwatch_alarm(instance_id, instance_name, metric_name, threshold, comparison_operator, evaluation_periods, alarm_name, alarm_description, cloudwatch_client,alarm_actions,instance_platform,instance_ami,instance_type):
    name_space = "AWS/EC2"

    if instance_platform == "Linux/UNIX" or "Debian":
        if metric_name == "disk_used_percent":
            name_space = "CWAgent"
            dimension_valido = [{"Name": "path", "Value": "/"},{'Name': 'InstanceId', 'Value': instance_id},{"Name": "ImageId", "Value": instance_ami},{"Name": "InstanceType", "Value": instance_type},{"Name": "device", "Value": "nvme0n1p1"},{"Name": "fstype", "Value": "ext4"}]  
        elif metric_name == "mem_used_percent":
            name_space = "CWAgent"
            dimension_valido =[{"Name": "InstanceId", "Value": instance_id},{"Name": "ImageId", "Value": instance_ami},{"Name": "InstanceType", "Value": instance_type}]
        else:
            dimension_valido = [{'Name': 'InstanceId', 'Value': instance_id}]
    
    if instance_platform == "Windows":
        if metric_name == "LogicalDisk % Free Space":
            name_space = "CWAgent"
            dimension_valido = [{"Name": "instance", "Value": "C:"},{"Name": "ImageId", "Value": instance_ami},{"Name": "objectname", "Value": "LogicalDisk"},{'Name': 'InstanceId', 'Value': instance_id}]
        elif metric_name == "Memory % Committed Bytes In Use":
            name_space = "CWAgent"
            dimension_valido = [{"Name": "ImageId", "Value": instance_ami},{"Name": "objectname", "Value": "Memory"},{"Name": "InstanceType", "Value": instance_type}]
        else:
            dimension_valido = [{'Name': 'InstanceId', 'Value': instance_id}]

    try:
        cloudwatch_client.put_metric_alarm(
            AlarmName=alarm_name,
            AlarmDescription=alarm_description,
            ActionsEnabled=True,
            MetricName=metric_name,
            Namespace=name_space,
            Statistic="Average",
            Dimensions=dimension_valido,
            Period=300,
            EvaluationPeriods=evaluation_periods,
            Threshold=threshold,
            AlarmActions = [alarm_actions],
            ComparisonOperator=comparison_operator
        )

        logging.info(f"Alarme '{alarm_name}' criado com sucesso para a instância {instance_name or instance_id}.")
    except ClientError as e:
        logging.error(f"Erro ao criar o alarme: {e}")
        
def role_exists(iam_client, role_name):
    try:
        iam_client.get_role(RoleName=role_name)
        return True  # A role existe
    except iam_client.exceptions.NoSuchEntityException:
        return False  # A role não existe

def instance_profile_exists(iam_client, instance_profile_name):
    try:
        iam_client.get_instance_profile(InstanceProfileName=instance_profile_name)
        return True  # O perfil de instância existe
    except iam_client.exceptions.NoSuchEntityException:
        return False  # O perfil de instância não existe
        
def is_role_associated_with_instance_profile(iam_client, instance_profile_name, role_name):
    try:
        response = iam_client.get_instance_profile(InstanceProfileName=instance_profile_name)
        for role in response['InstanceProfile']['Roles']:
            if role['RoleName'] == role_name:
                return True  # A role já está associada ao perfil de instância
        return False  # A role não está associada ao perfil de instância
    except ClientError as error:
        logging.error(f"Erro ao verificar a associação da role ao perfil de instância: {error}")
        return False  # Trate a exceção conforme necessário

def policy_attached(iam_client, role_name, policy_arn):
    try:
        response = iam_client.list_attached_role_policies(RoleName=role_name)
        for policy in response['AttachedPolicies']:
            if policy['PolicyArn'] == policy_arn:
                return True
        return False
    except ClientError as error:
        logging.error(f"Erro ao verificar políticas anexadas: {error}")
        return False

def create_role_with_policies(iam_client, role_name, policies_arns, assume_role_policy_document):
    # Verifica se a role já existe
    if not role_exists(iam_client, role_name):
        try:
            # Cria a role se não existir
            iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=assume_role_policy_document,
                Description='Role para instâncias EC2 com CloudWatch e SSM',
            )
            logging.info(f"Role {role_name} criada com sucesso.")
        except ClientError as error:
            logging.error(f"Erro ao criar a role {role_name}: {error}")
    else:
        logging.info(f"Role {role_name} já existe.")
        
    # Verifica antes de atachar cada política
    for policy_arn in policies_arns:
        if not policy_attached(iam_client, role_name, policy_arn):
            try:
                iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                logging.info(f"Política {policy_arn} atachada à role {role_name} com sucesso.")
            except ClientError as error:
                logging.error(f"Erro ao atachar política {policy_arn} à role {role_name}: {error}")
        else:
            logging.info(f"Política {policy_arn} já está atachada à role {role_name}.")
            
    # Verifica se o Instance Profile já existe
    instance_profile_name = role_name + "-profile"
    if not instance_profile_exists(iam_client, instance_profile_name):
        try:
            iam_client.create_instance_profile(InstanceProfileName=instance_profile_name)
            logging.info(f"Instance Profile '{instance_profile_name}' criado com sucesso.")
        except ClientError as error:
            logging.error(f"Erro ao criar Instance Profile '{instance_profile_name}': {error}")
    else:
        logging.info(f"Instance Profile '{instance_profile_name}' já existe.")
    
    # Aqui você verifica e associa a role ao perfil de instância
    if not is_role_associated_with_instance_profile(iam_client, instance_profile_name, role_name):
        try:
            iam_client.add_role_to_instance_profile(InstanceProfileName=instance_profile_name, RoleName=role_name)
            logging.info(f"Role '{role_name}' associada com sucesso ao Instance Profile '{instance_profile_name}'.")
        except ClientError as error:
            logging.error(f"Erro ao associar a role '{role_name}' ao perfil de instância '{instance_profile_name}': {error}")
    else:
        logging.info(f"A role '{role_name}' já está associada ao Instance Profile '{instance_profile_name}'.")

def create_sns_topic(sns):

    topics = sns.list_topics()
    topic_arn = next((topic['TopicArn'] for topic in topics['Topics'] if 'Dati-monitoramento' in topic['TopicArn']), None)
    if not topic_arn:
        topic = sns.create_topic(Name='Dati-monitoramento')
        topic_arn = topic['TopicArn']
    return topic_arn

def subscribe_sns_topic(sns_topic_arn, protocol, endpoint,sns):

    response = sns.subscribe(
        TopicArn=sns_topic_arn,
        Protocol=protocol,
        Endpoint=endpoint
    )

    logging.info(f"Inscrito no {protocol} endpoint {endpoint} no topico {sns_topic_arn}")

def tag_cloudwatch_alarm(alarm_name,event,cloudwatch_client):
    """
    Adiciona tags a um alarme do CloudWatch.
    """

    try:
        account_id = event.get('account_id')
        region = event.get("region")

        tags = {
            'Name': alarm_name,
            'Creator': 'Dati',
            'Provisioned': 'Automatic',
            'Sustained': 'Manual',
            'Product': 'CloudwatchAlarm'
        }

        cloudwatch_client.tag_resource(
            ResourceARN=f"arn:aws:cloudwatch:{region}:{account_id}:alarm:{alarm_name}",
            Tags=[{'Key': k, 'Value': v} for k, v in tags.items()]
        )

    except ClientError as e:
        logging.error(f"Erro ao adicionar tags ao alarme: {e}")

def attach_instance_profile(ec2_client, instance_id, instance_profile_name):
    try:
        ec2_client.associate_iam_instance_profile(
            InstanceId=instance_id,
            IamInstanceProfile={'Name': instance_profile_name}
        )
        logging.info(f"Perfil de instância {instance_profile_name} associado à instância {instance_id} com sucesso.")
    except ClientError as error:
        logging.error(f"Erro ao associar perfil de instância '{instance_profile_name}' à instância {instance_id}: {error}")

def format_instance_info(instance_info):
    return instance_info.get('Name') or instance_info['InstanceId']

def get_instance_profile_role(iam_client, instance_profile_arn):
    instance_profile_name = instance_profile_arn.split('/')[-1]
    
    try:
        response = iam_client.get_instance_profile(InstanceProfileName=instance_profile_name)
        roles = response['InstanceProfile']['Roles']
        if roles:
            return roles[0]['RoleName']
    except ClientError as error:
        logging.error(f"Erro ao obter o perfil de instância: {error}")
    return None

def attach_policies_to_role(iam_client, role_name, policies_arns):
    for policy_arn in policies_arns:
        try:
            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
            logging.info(f"Política {policy_arn} atachada à role {role_name} com sucesso.")
        except ClientError as error:
            logging.error(f"Erro ao atachar política {policy_arn} à role {role_name}: {error}")


def lambda_handler(event, context):
    account_id = event.get('account_id')
    region = event.get('region')
    credentials = assume_role(account_id, region)
    logging.info(f"Executando lambda para instalação de alertas do EC2 para conta {account_id}, na região{region}")

    if credentials:
        ec2_client = boto3.client(
            'ec2',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region
        )
        autoscaling_client = boto3.client(
            'autoscaling',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region
        )
        cloudwatch_client = boto3.client(
            'cloudwatch',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region
        )
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region
        )
        sns = boto3.client('sns',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
            
        required_policies = [
            'arn:aws:iam::aws:policy/AmazonSSMPatchAssociation',
            'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore',
            'arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy'
        ]
        assume_role_policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        })

        create_role_with_policies(iam_client, "Dati-CloudwatchAgent-Role", required_policies, assume_role_policy_document)

        sns_topic_arn = create_sns_topic(sns)
        subscribe_sns_topic(sns_topic_arn, 'sqs', 'arn:aws:sqs:us-east-1:386715143968:dati-monitoring-queue',sns)
        instances = get_all_ec2_instances(ec2_client, autoscaling_client)

        for instance_info in instances:
            instance_id = instance_info['InstanceId']
            instance_platform = instance_info['PlatformName']
            instance_state = instance_info['State']
            instance_profile_arn = instance_info.get('InstanceProfileArn')
            instance_ami = instance_info["ImageId"]
            instance_type = instance_info['InstanceType']

            instance_name = instance_info.get('Name', instance_id)
            logging.info(f'Atualizando a intancia {instance_id}, Plataforma {instance_platform}, Estado da instancia é {instance_state}')

            if not instance_profile_arn:
                attach_instance_profile(ec2_client, instance_id, "Dati-CloudwatchAgent-Role-profile")
            else:
                role_name = get_instance_profile_role(iam_client, instance_profile_arn)
                if role_name:
                    attach_policies_to_role(iam_client, role_name, required_policies)

            if instance_state in ["running", "stopped"]:
                create_alarms_for_instance(instance_id, instance_name, cloudwatch_client, event, sns_topic_arn, credentials, instance_platform, instance_ami, instance_type)
    else:
        logging.error("Não foi possível obter as credenciais para a role.")
