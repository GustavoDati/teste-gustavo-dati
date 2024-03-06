import boto3
from botocore.exceptions import ClientError
import time
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
    # Assume uma função IAM para obter credenciais temporárias
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

def create_sns_topic(sns_client):
    # Cria ou obtém um tópico SNS com o nome 'Dati-monitoramento'

    topics = sns_client.list_topics()['Topics']
    for topic in topics:
        if 'Dati-monitoramento' in topic['TopicArn']:
            return topic['TopicArn']

    response = sns_client.create_topic(Name='Dati-monitoramento')
    return response['TopicArn']

def subscribe_sns_topic(sns_client, sns_topic_arn, protocol, endpoint):

    # Lista as inscrições para o tópico SNS especificado
    subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)['Subscriptions']

    # Verifica se o endpoint já está inscrito e confirmado
    for subscription in subscriptions:
        if subscription['Endpoint'] == endpoint and subscription['SubscriptionArn'] != 'PendingConfirmation':
            logger.info(f"O endpoint já está inscrito e confirmado no tópico SNS.")
            return  # Sai da função sem criar uma nova inscrição

    # Se o endpoint não estiver inscrito ou não estiver confirmado, inscreve o endpoint
    response = sns_client.subscribe(
        TopicArn=sns_topic_arn,
        Protocol=protocol,
        Endpoint=endpoint
    )
    logger.info(f"Inscrição realizada com sucesso.")

def get_all_sqs_queues(sqs_client):
    queues = []

    try:
        response = sqs_client.list_queues()
        if 'QueueUrls' in response:
            queues = response['QueueUrls']
    except ClientError as e:
        logging.error(f"Erro ao obter filas SQS: {e}")

    return queues

def create_cloudwatch_alarm(queue_url, metric_name, threshold, comparison_operator, evaluation_periods, alarm_name, alarm_description, alarm_actions, cloudwatch_client):
    try:
        cloudwatch_client.put_metric_alarm(
            AlarmName=alarm_name,
            AlarmDescription=alarm_description,
            ActionsEnabled=True,
            MetricName=metric_name,
            Namespace="AWS/SQS",
            Statistic="SampleCount",
            Dimensions=[{'Name': 'QueueName', 'Value': queue_url.split("/")[-1]}],
            Period=300,
            EvaluationPeriods=evaluation_periods,
            Threshold=threshold,
            AlarmActions=[alarm_actions],
            ComparisonOperator=comparison_operator
        )
    except ClientError as e:
        logging.error(f"Erro ao criar o alarme: {e}")

def tag_cloudwatch_alarm(alarm_name, cloudwatch_client, credentials, event, region):
    account_id = event.get('account_id')
    tags = {
        'Name': alarm_name,
        'Creator': 'Dati',
        'Provisioned': 'Automatic',
        'Sustained': 'Manual',
        'Product': 'CloudwatchAlarm'
    }
    try:
        cloudwatch_client.tag_resource(
            ResourceARN=f"arn:aws:cloudwatch:{region}:{account_id}:alarm:{alarm_name}",
            Tags=[{'Key': k, 'Value': v} for k, v in tags.items()]
        )
    except ClientError as e:
        logging.error(f"Erro ao adicionar tags ao alarme: {e}")

def create_alarms_for_sqs(queue_url, cloudwatch_client, sns_topic_arn, event):
    metrics = {
        'NumberOfMessagesDeleted': {'unit': 'Count', 'threshold': 1},
        'ApproximateNumberOfMessagesDelayed': {'unit': 'Count', 'threshold': 1},
        'ApproximateAgeOfOldestMessage': {'unit': 'Seconds', 'threshold': 3600}
    }

    for metric, info in metrics.items():
        threshold = info['threshold']
        alarm_name = f"{queue_url.split('/')[-1]} {metric} Alarm"
        alarm_description = f"Alarme quando {metric} excede {threshold} {info['unit']}"

        create_cloudwatch_alarm(
            queue_url=queue_url,
            metric_name=metric,
            threshold=threshold,
            comparison_operator='GreaterThanThreshold',
            evaluation_periods=2,
            alarm_name=alarm_name,
            alarm_description=alarm_description,
            alarm_actions=sns_topic_arn,
            cloudwatch_client=cloudwatch_client
        )
        
        tag_cloudwatch_alarm(alarm_name, event, cloudwatch_client)

def lambda_handler(event, context):
    account_id = event.get('account_id')
    region = event.get('region')  # Ensure the region is passed in the event
    credentials = assume_role(account_id, region)

    if credentials:
        cloudwatch_client = boto3.client(
            'cloudwatch',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        sqs_client = boto3.client('sqs',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        sns_client = boto3.client('sns',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )  

        sns_topic_arn = create_sns_topic(sns_client)
        subscribe_sns_topic(sns_client, sns_topic_arn, 'sqs', 'arn:aws:sqs:us-east-1:386715143968:dati-monitoring-queue')

        sqs_queues = get_all_sqs_queues(sqs_client)
        
        for queue_url in sqs_queues:
            create_alarms_for_sqs(queue_url, cloudwatch_client, sns_topic_arn, event)
            time.sleep(2)

        logging.info(f"Alarmes e tags criados com sucesso para {len(sqs_queues)} filas SQS.")
    else:
        logging.error("Não foi possível obter as credenciais para a role.")
