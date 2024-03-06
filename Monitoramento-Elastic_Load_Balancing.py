import boto3
from botocore.exceptions import ClientError
import time
import random
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

def get_all_load_balancers(credentials, region):
    elb_client = boto3.client('elbv2',
        region_name=region,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    load_balancers = []
    try:
        response = elb_client.describe_load_balancers()
        for elb in response['LoadBalancers']:
            load_balancers.append({
                'Name': elb['LoadBalancerName'],
                'Type': elb['Type']  # 'application' ou 'network' para ALB/NLB, respectivamente
            })
    except ClientError as e:
        logging.error(f"Erro ao obter Load Balancers: {e}")

    # Para CLBs, você precisará usar um cliente ELB separado e adicionar esses LBs à lista
    elb_client_v1 = boto3.client('elb', 
        region_name=region,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    try:
        response = elb_client_v1.describe_load_balancers()
        for elb in response['LoadBalancerDescriptions']:
            load_balancers.append({
                'Name': elb['LoadBalancerName'],
                'Type': 'classic'  # Adiciona CLBs com o tipo 'classic'
            })
    except ClientError as e:
        logging.error(f"Erro ao obter CLBs: {e}")

    return load_balancers
    
def backoff_exponencial(tentativa, max_tentativa=5, tempo_inicial=1, fator=2, max_tempo=30):
    """Calcula o tempo de espera com backoff exponencial e jitter."""
    if tentativa < max_tentativa:
        tempo = min(tempo_inicial * (fator ** tentativa), max_tempo)
        # Adiciona jitter para evitar que várias chamadas sejam refeitas ao mesmo tempo
        tempo_com_jitter = tempo + random.uniform(0, tempo * 0.2)
        return tempo_com_jitter
    else:
        # Se atingir o número máximo de tentativas, levanta uma exceção
        raise Exception("Número máximo de tentativas de backoff atingido.")

def create_cloudwatch_alarm(resource_id, metric_name, threshold, comparison_operator, evaluation_periods, alarm_name, alarm_description, cloudwatch_client, alarm_actions, namespace):
    try:
        cloudwatch_client.put_metric_alarm(
            AlarmName=alarm_name,
            AlarmDescription=alarm_description,
            ActionsEnabled=True,
            MetricName=metric_name,
            Namespace=namespace,  
            Statistic="Average",
            Dimensions=[{'Name': 'LoadBalancer', 'Value': resource_id}],
            Period=60,
            EvaluationPeriods=evaluation_periods,
            Threshold=threshold,
            AlarmActions=[alarm_actions],
            ComparisonOperator=comparison_operator
        )
        return True, f"Alarme {alarm_name} criado com sucesso."
    except ClientError as e:
        return False, f"Erro ao criar o alarme {alarm_name}: {e}"

def tag_cloudwatch_alarm(alarm_name, event, cloudwatch_client):
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
            'NormalState': 'InsufficientData',
            'Product': 'CloudwatchAlarm'
        }

        cloudwatch_client.tag_resource(
            ResourceARN=f"arn:aws:cloudwatch:{region}:{account_id}:alarm:{alarm_name}",
            Tags=[{'Key': k, 'Value': v} for k, v in tags.items()]
        )

    except ClientError as e:
        logging.error(f"Erro ao adicionar tags ao alarme: {e}")
        
def create_alarms_for_elb(elb_info, cloudwatch_client, event, sns_topic_arn):
    alarm_results = {'success': [], 'failed': []}

    # Define métricas comuns para todos os tipos de Load Balancers
    common_metrics = {
        'HTTPCode_Backend_4XX': 10,
        'HTTPCode_Backend_5XX': 5
    }

    # Métricas específicas para ALBs e NLBs
    alb_nlb_metrics = {
        'UnHealthyHostCount': 1,
        'Latency': 0.3
    }

    # Métricas específicas para CLBs
    clb_metrics = {
        'HTTPCode_ELB_5XX': 5,
        'SurgeQueueLength': 10
    }

    # Escolhe o conjunto correto de métricas e o namespace baseado no tipo de Load Balancer
    if elb_info['Type'] in ['application', 'network']:
        metrics = {**common_metrics, **alb_nlb_metrics}
        namespace = f"AWS/{elb_info['Type'].capitalize()}ELB"
    else:  # Classic Load Balancer
        metrics = {**common_metrics, **clb_metrics}
        namespace = "AWS/ELB"

    for metric, threshold in metrics.items():
        alarm_name = f"{elb_info['Name']}_{metric}_Alarm"
        alarm_description = f"Alarme quando {metric} excede {threshold}"
        
        success, message = create_cloudwatch_alarm(
            resource_id=elb_info['Name'],
            metric_name=metric,
            threshold=threshold,
            comparison_operator='GreaterThanThreshold',
            evaluation_periods=4,
            alarm_name=alarm_name,
            alarm_description=alarm_description,
            cloudwatch_client=cloudwatch_client,
            alarm_actions=sns_topic_arn,
            namespace=namespace 
        )

        if success:
            alarm_results['success'].append(alarm_name)
        else:
            alarm_results['failed'].append(message)

        tag_cloudwatch_alarm(alarm_name, event, cloudwatch_client)

    return alarm_results

def lambda_handler(event, context):
    account_id = event.get('account_id')
    region = event.get('region')  # Certifique-se de que a região é passada no evento de entrada
    credentials = assume_role(account_id, region)
    logging.info(f"Executando lambda para instalação de alertas do Elastic Load Balancer para conta {account_id}, na região{region}")

    if credentials:
        cloudwatch_client = boto3.client(
            'cloudwatch',
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

        elbs = get_all_load_balancers(credentials, region)

        for elb_info in elbs:
            create_alarms_for_elb(elb_info, cloudwatch_client, event, sns_topic_arn)

        logging.info(f"Alarmes e tags criados com sucesso para {len(elbs)} ELBs.")
    else:
        logging.error("Não foi possível obter as credenciais para a role.")
