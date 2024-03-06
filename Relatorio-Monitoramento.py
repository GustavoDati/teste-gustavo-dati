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
        logging.error(f"Erro ao tentar assumir a role: {error}")
        return None

def check_alarms(instance_id, expected_metrics, cloudwatch_client, resource_type):
    missing_alarms = []
    incomplete_alarms = []

    metrics_coverage = {metric: False for metric in expected_metrics}

    try:
        paginator = cloudwatch_client.get_paginator('describe_alarms')
        page_iterator = paginator.paginate()

        for page in page_iterator:
            for alarm in page['MetricAlarms']:
                if any(d['Value'] == instance_id for d in alarm['Dimensions']) and alarm['MetricName'] in expected_metrics:
                    metrics_coverage[alarm['MetricName']] = True

                    if not alarm['AlarmActions']:
                        incomplete_alarms.append({
                            'ResourceID': instance_id,
                            'Metric': alarm['MetricName'],
                            'AlarmName': alarm['AlarmName'],
                            'ResourceType': resource_type
                        })

        for metric, covered in metrics_coverage.items():
            if not covered:
                missing_alarms.append({'ResourceID': instance_id, 'Metric': metric, 'ResourceType': resource_type})

    except ClientError as e:
        logging.error(f"Erro ao descrever alarmes: {e}")

    return missing_alarms, incomplete_alarms

def is_instance_in_autoscaling_group(instance_id, autoscaling_client):
    try:
        response = autoscaling_client.describe_auto_scaling_instances(InstanceIds=[instance_id])
        return len(response['AutoScalingInstances']) > 0
    except ClientError as e:
        logging.error(f"Erro ao verificar grupo Auto Scaling da instância: {e}")
        return False

def lambda_handler(event, context):
    account_id = event.get('account_id')
    region = event.get('region')
    credentials = assume_role(account_id, region)

    if credentials is None:
        return {"Error": "Não foi possível assumir a role especificada."}

    cloudwatch_client = boto3.client(
        'cloudwatch',
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

    rds_client = boto3.client(
        'rds',
        region_name=region,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    ec2_client = boto3.client(
        'ec2',
        region_name=region,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    report = {'MissingAlarms': [], 'IncompleteAlarms': []}

    # Defina aqui as métricas esperadas para as instâncias EC2
    expected_ec2_metrics = [
        'CPUUtilization', 'NetworkOut', 'StatusCheckFailed_Instance',
        'StatusCheckFailed_System', 'mem_used_percent', 'disk_used_percent'
    ]

    # EC2 Instances
    ec2_response = ec2_client.describe_instances()
    for reservation in ec2_response['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            # Verifica se a instância deve ser ignorada com base na tag
            ignore_instance = False
            if 'Tags' in instance:
                for tag in instance['Tags']:
                    if tag['Key'] == 'Monitoramento' and tag['Value'].lower() == 'não':
                        ignore_instance = True
                        break
            if ignore_instance:
                continue  # Ignora esta instância

            instance_name = instance_id
            if 'Tags' in instance:
                for tag in instance['Tags']:
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break

            if not is_instance_in_autoscaling_group(instance_id, autoscaling_client):
                missing_alarms, incomplete_alarms = check_alarms(instance_id, expected_ec2_metrics, cloudwatch_client, 'EC2')
                for alarm in incomplete_alarms + missing_alarms:
                    alarm['ResourceID'] = instance_name

                report['MissingAlarms'].extend(missing_alarms)
                report['IncompleteAlarms'].extend(incomplete_alarms)

    # Gerar relatório
    if report['MissingAlarms'] or report['IncompleteAlarms']:
        logging.info("Relatório de Conformidade de Alarmes:")
        if report['MissingAlarms']:
            logging.info("Alarmes faltando:")
            for item in report['MissingAlarms']:
                logging.info(f"Tipo: {item['ResourceType']}, ID do Recurso: {item['ResourceID']}, Métrica: {item['Metric']}")
        if report['IncompleteAlarms']:
            logging.info("Alarmes sem ações definidas:")
            for item in report['IncompleteAlarms']:
                logging.info(f"Tipo: {item['ResourceType']}, ID do Recurso: {item['ResourceID']}, Métrica: {item['Metric']}, Alarme: {item['AlarmName']}")

    return report
