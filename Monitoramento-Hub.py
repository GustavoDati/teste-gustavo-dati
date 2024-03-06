import boto3
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

def lambda_handler(event, context):
    s3_client = boto3.client('s3')
    lambda_client = boto3.client('lambda')

    # Obter informações do arquivo do bucket S3
    bucket_name = event['Records'][0]['s3']['bucket']['name']
    file_name = event['Records'][0]['s3']['object']['key']

    # Ler o arquivo do S3
    file_obj = s3_client.get_object(Bucket=bucket_name, Key=file_name)
    file_content = file_obj['Body'].read().decode('utf-8')

    # Extrair as últimas três linhas (considerando a última linha vazia)
    lines = file_content.split('\n')
    account_id, region, services = lines[-4].strip(), lines[-3].strip(), lines[-2].strip()

    # Preparar os dados para invocar outra função Lambda
    payload = {
        "account_id": account_id,
        "region": region
    }
    

    # Se 'services' for 'Todos', invocar todas as funções
    if services.strip() == 'Todos':
        logging.info(f"Executando lambda que aciona TODOS os lambdas para conta {account_id}, na região{region}")
        for function in lambda_client.list_functions()['Functions']:
            if function['FunctionName'].startswith('Monitoramento-'):
                lambda_client.invoke(
                    FunctionName=function['FunctionName'],
                    InvocationType='Event',
                    Payload=json.dumps(payload)
                )
    else:
        # Lógica atual para serviços específicos
        for service in services.split(','):
            function_name = f"Monitoramento-{service.strip()}"
            logging.info(f"Executando o lambda {function_name} para conta {account_id}, na região{region}")
            lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='Event',
                Payload=json.dumps(payload)
            )

    logging.info(f'Sucesso ao invocar o Lambda functions para o serviço: {services}')
