import boto3
from botocore.exceptions import ClientError
import time
import re
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
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="LambdaSession"
        )
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
        response = ec2_client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]
        )
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                image_id = instance['ImageId']
                image = ec2_client.describe_images(ImageIds=[image_id])

                platform_description = image['Images'][0]['Description'].lower()
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
                    'State': [instance['State']['Name']],
                }

                if not is_instance_in_autoscaling_group(instance['InstanceId'], autoscaling_client):
                    instances.append(instance_info)
        return instances
    except ClientError as error:
        logging.error(f"Erro ao listar instâncias EC2: {error}")
        return []

def check_disk_space_windows(instance_id, ssm_client):
    commands = ["(Get-PSDrive C).Free / 1GB -as [int]"]
    response = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunPowerShellScript",
        Parameters={"commands": commands},
        TimeoutSeconds=30
    )
    command_id = response['Command']['CommandId']
    time.sleep(2)
    output = ssm_client.get_command_invocation(
        CommandId=command_id,
        InstanceId=instance_id
    )
    
    # Verifica se o StandardOutputContent contém um valor numérico antes de converter para int
    if output['StandardOutputContent'].strip().isdigit():
        return int(output['StandardOutputContent']) >= 2
    else:
        logging.error(f"Saída inesperada para a instância {instance_id}: {output['StandardOutputContent']}")
        return False

def check_disk_space_linux(instance_id, ssm_client):
    commands = ["df -BG / | tail -1 | awk '{print $4}' | sed 's/G//'"]
    response = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
        TimeoutSeconds=30
    )
    command_id = response['Command']['CommandId']
    output = ssm_client.get_command_invocation(
        CommandId=command_id,
        InstanceId=instance_id
    )
    match = re.search(r'\d+', output['StandardOutputContent'])
    if match:
        return int(match.group()) >= 2
    else:
        logging.error("Não foi possível determinar o espaço em disco.")
        return False

def ssm_run_command(instance_id, instance_platform, ssm_client):
    commands = []  # Inicializa a variável commands com uma lista vazia
    
    # Verifica se o espaço em disco é suficiente antes de definir os comandos
    if instance_platform in ["Linux/UNIX", "Debian", "Amazon Linux", "Windows"]:
        disk_check_function = check_disk_space_linux if instance_platform != "Windows" else check_disk_space_windows
        if not disk_check_function(instance_id, ssm_client):
            logging.error(f"Erro: Instância {instance_id}: Espaço insuficiente em disco.")
            return

    # Comandos específicos para cada plataforma
    if instance_platform == "Ubuntu":
        commands = [
            "if [ -d '/opt/aws/amazon-cloudwatch-agent' ]; then echo 'CloudWatch Agent já está instalado.'; else echo 'Instalando CloudWatch Agent...'; " +
            "wget https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb",
            "sleep 30",
            "sudo dpkg -i -E ./amazon-cloudwatch-agent.deb",
            "sleep 15",
            "rm /opt/aws/amazon-cloudwatch-agent/bin/config.json",
            "sleep 2",
            "",
            'echo \'{"agent": {"metrics_collection_interval": 1, "run_as_user": "cwagent"}, "metrics": {"aggregation_dimensions": [["InstanceId"]], "append_dimensions": {"AutoScalingGroupName": "${aws:AutoScalingGroupName}", "ImageId": "${aws:ImageId}", "InstanceId": "${aws:InstanceId}", "InstanceType": "${aws:InstanceType}"}, "metrics_collected": {"cpu": {"measurement": ["cpu_usage_idle", "cpu_usage_iowait", "cpu_usage_user", "cpu_usage_system"], "metrics_collection_interval": 1, "totalcpu": false}, "disk": {"measurement": ["used_percent", "inodes_free"], "metrics_collection_interval": 1, "resources": ["*"]}, "diskio": {"measurement": ["io_time"], "metrics_collection_interval": 1, "resources": ["*"]}, "mem": {"measurement": ["mem_used_percent"], "metrics_collection_interval": 1}, "swap": {"measurement": ["swap_used_percent"], "metrics_collection_interval": 1}}}}\' > config.json',
            "",
            "mv ./config.json /opt/aws/amazon-cloudwatch-agent/bin/",
            "sleep 2",
            "sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s"
        ]

        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            DocumentVersion="1",
            Parameters={
                "commands": commands,
                "workingDirectory": [""],
                "executionTimeout": ["3600"]
            },
            TimeoutSeconds=600,
            MaxConcurrency="50",
            MaxErrors="0"
        )
        logging.info(response)
    elif instance_platform == "Debian":
        commands = [
            "if [ -d '/opt/aws/amazon-cloudwatch-agent' ]; then echo 'CloudWatch Agent já está instalado.'; else echo 'Instalando CloudWatch Agent...'; " +
            "wget https://amazoncloudwatch-agent.s3.amazonaws.com/debian/amd64/latest/amazon-cloudwatch-agent.deb",
            "sleep 30",
            "sudo dpkg -i -E ./amazon-cloudwatch-agent.deb",
            "sleep 15",
            "rm /opt/aws/amazon-cloudwatch-agent/bin/config.json",
            "sleep 2",
            "",
            'echo \'{"agent": {"metrics_collection_interval": 1, "run_as_user": "cwagent"}, "metrics": {"aggregation_dimensions": [["InstanceId"]], "append_dimensions": {"AutoScalingGroupName": "${aws:AutoScalingGroupName}", "ImageId": "${aws:ImageId}", "InstanceId": "${aws:InstanceId}", "InstanceType": "${aws:InstanceType}"}, "metrics_collected": {"cpu": {"measurement": ["cpu_usage_idle", "cpu_usage_iowait", "cpu_usage_user", "cpu_usage_system"], "metrics_collection_interval": 1, "totalcpu": false}, "disk": {"measurement": ["used_percent", "inodes_free"], "metrics_collection_interval": 1, "resources": ["*"]}, "diskio": {"measurement": ["io_time"], "metrics_collection_interval": 1, "resources": ["*"]}, "mem": {"measurement": ["mem_used_percent"], "metrics_collection_interval": 1}, "swap": {"measurement": ["swap_used_percent"], "metrics_collection_interval": 1}}}}\' > config.json',
            "",
            "mv ./config.json /opt/aws/amazon-cloudwatch-agent/bin/",
            "sleep 2",
            "sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s"
        ]

        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            DocumentVersion="1",
            Parameters={
                "commands": commands,
                "workingDirectory": [""],
                "executionTimeout": ["3600"]
            },
            TimeoutSeconds=600,
            MaxConcurrency="50",
            MaxErrors="0"
        )
        logging.info(response)
    elif instance_platform == "Amazon Linux":
        commands = [
            "if [ -d '/opt/aws/amazon-cloudwatch-agent' ]; then echo 'CloudWatch Agent já está instalado.'; else echo 'Instalando CloudWatch Agent...'; " +
            "wget https://amazoncloudwatch-agent.s3.amazonaws.com/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm",
            "sleep 30",
            "sudo rpm -U ./amazon-cloudwatch-agent.rpm",  # Comando corrigido para usar rpm
            "sleep 15",
            "rm /opt/aws/amazon-cloudwatch-agent/bin/config.json",
            "sleep 2",
            "",
            'echo \'{"agent": {"metrics_collection_interval": 1, "run_as_user": "cwagent"}, "metrics": {"aggregation_dimensions": [["InstanceId"]], "append_dimensions": {"AutoScalingGroupName": "${aws:AutoScalingGroupName}", "ImageId": "${aws:ImageId}", "InstanceId": "${aws:InstanceId}", "InstanceType": "${aws:InstanceType}"}, "metrics_collected": {"cpu": {"measurement": ["cpu_usage_idle", "cpu_usage_iowait", "cpu_usage_user", "cpu_usage_system"], "metrics_collection_interval": 1, "totalcpu": false}, "disk": {"measurement": ["used_percent", "inodes_free"], "metrics_collection_interval": 1, "resources": ["*"]}, "diskio": {"measurement": ["io_time"], "metrics_collection_interval": 1, "resources": ["*"]}, "mem": {"measurement": ["mem_used_percent"], "metrics_collection_interval": 1}, "swap": {"measurement": ["swap_used_percent"], "metrics_collection_interval": 1}}}}\' > config.json',
            "",
            "mv ./config.json /opt/aws/amazon-cloudwatch-agent/bin/",
            "sleep 2",
            "sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s"
        ]

        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={
                "commands": commands,
                "workingDirectory": [""],
                "executionTimeout": ["3600"]
            },
            TimeoutSeconds=600,
            MaxConcurrency="50",
            MaxErrors="0"
        )
        logging.info(response)
    elif instance_platform == "Windows":
        commands = [
            "if (Get-Service 'AmazonCloudWatchAgent' -ErrorAction SilentlyContinue) { Write-Host 'CloudWatch Agent já está instalado.' } else { Write-Host 'Instalando CloudWatch Agent...'; " +
            r"cd 'C:\Program Files\Amazon\AmazonCloudWatchAgent'",
            '$token = Invoke-RestMethod -Method Put -Uri http://169.254.169.254/latest/api/token -Headers @{"X-aws-ec2-metadata-token-ttl-seconds"="21600"} -UseBasicParsing',
            '$instanceId = Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/instance-id -Headers @{"X-aws-ec2-metadata-token"=$token} -UseBasicParsing',
            '$imageId = Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/ami-id -Headers @{"X-aws-ec2-metadata-token"=$token} -UseBasicParsing',
            '$instanceType = Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/instance-type -Headers @{"X-aws-ec2-metadata-token"=$token} -UseBasicParsing',
            '(Invoke-WebRequest -Uri "https://amazoncloudwatch-agent.s3.amazonaws.com/windows/amd64/latest/amazon-cloudwatch-agent.msi" -OutFile .\\amazon-cloudwatch-agent.msi -UseBasicParsing).Links.Href',
            "timeout /t 180",
            'Start-Process .\\amazon-cloudwatch-agent.msi -ArgumentList "/quiet /passive"',
            "timeout /t 30",
            r"cd 'C:\Program Files\Amazon\AmazonCloudWatchAgent'",
            "timeout /t 2",
            """Set-Content -Path "C:\\Program Files\\Amazon\\AmazonCloudWatchAgent\\config.json" -Value @""",
            '{',
            '"metrics": {',
                '"aggregation_dimensions": [[',
                '["InstanceId"]',
                ']],',
                '"append_dimensions": {',
                '"ImageId": "${ImageId}",',
                '"InstanceId": "${InstanceId}",',
                '"InstanceType": "${InstanceType}"',
                '},',
                '"metrics_collected": {',
                '"LogicalDisk": {',
                    '"measurement": ["% Free Space"],',
                    '"metrics_collection_interval": 1,',
                    '"resources": ["*"]',
                '},',
                '"Memory": {',
                    '"measurement": ["% Committed Bytes In Use"],',
                    '"metrics_collection_interval": 1',
                '},',
                '"PagingFile": {',
                    '"measurement": ["% Usage"],',
                    '"metrics_collection_interval": 1,',
                    '"resources": ["*"]',
                '},',
                '"PhysicalDisk": {',
                    '"measurement": ["% Disk Time"],',
                    '"metrics_collection_interval": 1,',
                    '"resources": ["*"]',
                '},',
                '"Processor": {',
                    '"measurement": ["% User Time", "% Idle Time", "% Interrupt Time"],',
                    '"metrics_collection_interval": 1,',
                    '"resources": ["_Total"]',
                '}',
                '}',
            '}',
            '}@',
            '& "C:\\Program Files\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent-ctl.ps1" -a fetch-config -m ec2 -s -c file:.\\config.json'
            ]
        
    # Envio do comando via SSM
    if commands:
        try:
            response = ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript" if instance_platform not in ["Windows"] else "AWS-RunPowerShellScript",
                Parameters={"commands": commands},
                TimeoutSeconds=600
            )
            logging.info(f"Instância {instance_id}: Comandos enviados com sucesso. CommandId: {response['Command']['CommandId']}")
        except ClientError as error:
            logging.error(f"Instância {instance_id}: Falha ao enviar comandos. Erro: {error}")
    else:
        logging.error(f"Instância {instance_id}: Nenhum comando definido para a execução.")

def ssm_check_status(ssm_client, instance_id):
    try:
        response = ssm_client.get_connection_status(Target=instance_id)
        return response['Status'] == 'connected'
    except Exception as e:
        logging.error(f"Error: {e}")
        return False

def lambda_handler(event, context):
    account_id = event.get('account_id')
    region = event.get('region')
    credentials = assume_role(account_id, region)
    logging.info(f"Executando lambda para instalação de alertas do Cloudwatch Agent para conta {account_id}, na região{region}")
        
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
        ssm_client = boto3.client(
            'ssm',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region
        )
        instances = get_all_ec2_instances(ec2_client, autoscaling_client)

        for instance_info in instances:
            instance_id = instance_info['InstanceId']
            instance_platform = instance_info['PlatformName']  # Agora contém o SO inferido
            instance_state = instance_info['State']
        
            logging.info(f"Instance ID: {instance_id}, Platform: {instance_platform}")
            if instance_state == ["running"]:
                if ssm_check_status(ssm_client, instance_id):
                    ssm_run_command(instance_id, instance_platform, ssm_client)
                    logging.info(f"Instalado CloudWatch Agent na instnacia {instance_id}")
            else:
                logging.error(f"{instance_id} é inacessível, instale a CloudWatch Agent manualmente.")      
    else:
        logging.error("Não foi possível obter as credenciais para a role.")
