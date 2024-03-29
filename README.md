# AWS Monitoring Project

## Descrição

Este projeto contém scripts Python para o monitoramento de serviços AWS, incluindo EC2, DynamoDB, ECS, Elastic Beanstalk, Elastic Load Balancing, Lambda, RDS e SQS. Cada script configura alarmes no CloudWatch para métricas relevantes e envia notificações via SNS.

## Scripts

- `Monitoramento-DynamoDB.py`: Monitora tabelas DynamoDB.
- `Monitoramento-EC2.py`: Monitora instâncias EC2.
- `Monitoramento-EC2_CloudwatchAgent.py`: Configura o agente CloudWatch em instâncias EC2.
- `Monitoramento-ECS.py`: Monitora clusters ECS.
- `Monitoramento-Elastic_Beanstalk.py`: Monitora ambientes Elastic Beanstalk.
- `Monitoramento-Elastic_Load_Balancing.py`: Monitora Elastic Load Balancers.
- `Monitoramento-Lambda.py`: Monitora funções Lambda.
- `Monitoramento-RDS.py`: Monitora instâncias RDS.
- `Monitoramento-SQS.py`: Monitora filas SQS.
- `Monitoramento-Hub.py`: Script central que aciona os outros scripts de monitoramento.
- `Relatorio-Backup.py`: Gera relatórios de backup para instâncias EC2.
- `Relatorio-Monitoramento.py`: Verifica a configuração de alarmes de monitoramento para instâncias EC2.

## Configuração

Instruções detalhadas sobre como configurar cada script, incluindo permissões IAM necessárias, variáveis de ambiente e dependências.

## Uso

Como usar cada script, incluindo exemplos de comandos para executá-los.

## Contribuições

Detalhes sobre como contribuir para o projeto.

## Licença

Informações de licença do projeto.
