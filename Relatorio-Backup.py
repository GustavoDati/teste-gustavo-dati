import boto3
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def assume_role(account_id, region):
    role_arn = f"arn:aws:iam::{account_id}:role/Dati-acc-access2"
    sts_client = boto3.client('sts', region_name=region)
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="LambdaSession"
        )
        return response['Credentials']
    except ClientError as error:
        logger.error(f"Erro ao tentar assumir a role: {error}")
        return None

def is_instance_in_autoscaling_group(instance_id, autoscaling_client):
    try:
        response = autoscaling_client.describe_auto_scaling_instances(InstanceIds=[instance_id])
        return len(response['AutoScalingInstances']) > 0
    except ClientError as e:
        logger.error(f"Erro ao verificar grupo Auto Scaling da instância: {e}")
        return False

def get_instance_name(instance):
    for tag in instance.get('Tags', []):
        if tag['Key'] == 'Name':
            return tag['Value']
    return instance['InstanceId']

def check_backup(ec2_client, instance):
    instance_id = instance['InstanceId']
    instance_name = get_instance_name(instance)
    volumes_without_backup = []
    total_volumes_checked = 0

    try:
        response = ec2_client.describe_instance_attribute(
            InstanceId=instance_id,
            Attribute='blockDeviceMapping'
        )
        block_device_mappings = response.get('BlockDeviceMappings', [])

        for mapping in block_device_mappings:
            volume_id = mapping.get('Ebs', {}).get('VolumeId', '')
            if volume_id:
                total_volumes_checked += 1
                response = ec2_client.describe_snapshots(Filters=[
                    {'Name': 'volume-id', 'Values': [volume_id]},
                    {'Name': 'status', 'Values': ['completed']}
                ])
                snapshots = response.get('Snapshots', [])
                if not snapshots:
                    volumes_without_backup.append(volume_id)

        if total_volumes_checked > 0 and len(volumes_without_backup) == total_volumes_checked:
            logger.info(f"Instância {instance_name} ({instance_id}) sem backup em nenhum volume.")
            return instance_name, ["Sem backup em nenhum volume"]
        elif volumes_without_backup:
            for volume in volumes_without_backup:
                logger.info(f"Instância {instance_name} ({instance_id}) sem backup no volume: {volume}.")
            return instance_name, volumes_without_backup

    except ClientError as e:
        logger.error(f"Erro ao verificar backup da instância {instance_id}: {e}")

    return instance_name, []

def lambda_handler(event, context):
    account_id = event.get('account_id')
    region = event.get('region')
    credentials = assume_role(account_id, region)

    if credentials is None:
        return {"Error": "Não foi possível assumir a role especificada."}

    ec2_client = boto3.client(
        'ec2',
        region_name=region,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    autoscaling_client = boto3.client(
        'autoscaling',
        region_name=region,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    report = {}

    ec2_response = ec2_client.describe_instances()
    for reservation in ec2_response['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']

            # Verifica se a instância tem a tag Monitoramento com o valor não
            if any(tag['Key'] == 'Monitoramento' and tag['Value'].lower() == 'não' for tag in instance.get('Tags', [])):
                continue  # Pula esta instância

            # Pula a verificação se a instância estiver em um grupo de Auto Scaling
            if is_instance_in_autoscaling_group(instance_id, autoscaling_client):
                continue

            instance_name, backup_info = check_backup(ec2_client, instance)
            
            if backup_info:  # Adiciona ao relatório somente se houver volumes sem backup
                report[instance_name] = backup_info

    # Gerar relatório
    if report:
        logger.info("Relatório de Backup das Instâncias EC2:")
        for instance_name, backup_info in report.items():
            logger.info(f"Instância: {instance_name} - Sem backup configurado em: {', '.join(backup_info)}")
    else:
        logger.info("Todas as instâncias EC2 verificadas, que não estão em grupos de Auto Scaling e não têm a tag Monitoramento configurada como 'não', possuem backup configurado.")

    return report
