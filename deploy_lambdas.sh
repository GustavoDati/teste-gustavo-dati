#!/bin/bash

# Lista de suas funções Lambda e os scripts correspondentes
declare -A lambdas=(
    ["ProcessData"]="process_data.py"
    ["SendNotification"]="send_notification.py"
    # Adicione o restante das suas funções e scripts aqui
)

for lambda_name in "${!lambdas[@]}"; do
    script_name=${lambdas[$lambda_name]}
    
    echo "Empacotando e atualizando $lambda_name usando $script_name"
    
    # Zipa o script da função
    zip -j "$lambda_name.zip" "$script_name"
    
    # Atualiza a função Lambda correspondente
    aws lambda update-function-code --function-name "$lambda_name" --zip-file fileb://"$lambda_name.zip" --region sua-região-aws
    
    # Limpa o arquivo zip após o deploy
    rm "$lambda_name.zip"
done
