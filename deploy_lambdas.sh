#!/bin/bash

# Mapeamento de nome da função Lambda para arquivo de script Python
declare -A lambdas=(
    ["Monitoramento-DynamoDB"]="Monitoramento-DynamoDB.py"
    ["Monitoramento-EC2"]="Monitoramento-EC2.py"
    ["Monitoramento-EC2_CloudwatchAgent"]="Monitoramento-EC2_CloudwatchAgent.py"
    ["Monitoramento-ECS"]="Monitoramento-ECS.py"
    ["Monitoramento-Elastic_Beanstalk"]="Monitoramento-Elastic_Beanstalk.py"
    ["Monitoramento-Elastic_Load_Balancing"]="Monitoramento-Elastic_Load_Balancing.py"
    ["Monitoramento-Hub"]="Monitoramento-Hub.py"
    ["Monitoramento-Lambda"]="Monitoramento-Lambda.py"
    ["Monitoramento-RDS"]="Monitoramento-RDS.py"
    ["Monitoramento-SQS"]="Monitoramento-SQS.py"
    ["Relatorio-Backup"]="Relatorio-Backup.py"
    ["Relatorio-Monitoramento"]="Relatorio-Monitoramento.py"
)

# Configura a região da AWS, substitua pela sua região
AWS_REGION="us-east-1"

# Atualiza todas as funções Lambda
for lambda_name in "${!lambdas[@]}"; do
    script_name=${lambdas[$lambda_name]}
    
    echo "Empacotando e atualizando $lambda_name com $script_name"
    
    # Cria o arquivo zip
    zip -j "$lambda_name.zip" "$script_name"
    
    # Checa se o arquivo zip foi criado com sucesso
    if [ -f "$lambda_name.zip" ]; then
        # Atualiza a função Lambda na AWS
        aws lambda update-function-code --function-name "$lambda_name" --zip-file fileb://"$lambda_name.zip" --region $AWS_REGION
        
        # Remove o arquivo zip depois do upload
        rm "$lambda_name.zip"
    else
        echo "Falha ao criar o arquivo zip para $lambda_name"
    fi
done
