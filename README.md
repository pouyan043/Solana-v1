#Set Up .env File: Create a .env file in the project folder. Choose one transaction type:

#One-to-One SOL Transfer (solana-single or empty):

TRANSACTION_TYPE=
DESTINATION_ADDRESS=5oNDLk7eMo6gZqW7PhX3mZ8r49u5z6Y8No3p59vUbjZ
RPC_ENDPOINT=https://rpc.helius.xyz/?api-key=your_helius_api_key
VAULT_URL=https://your-vault-instance.com
VAULT_TOKEN=your_vault_token

#Multi-Destination SOL Transfer (solana-multi):

TRANSACTION_TYPE=solana-multi
DESTINATIONS=address1:1000000,address2:2000000
RPC_ENDPOINT=https://rpc.helius.xyz/?api-key=your_helius_api_key
VAULT_URL=https://your-vault-instance.com
VAULT_TOKEN=your_vault_token

#Single SPL Token Transfer (token-single):

TRANSACTION_TYPE=token-single
DESTINATIONS=5oNDLk7eMo6gZqW7PhX3mZ8r49u5z6Y8No3p59vUbjZ
MINT_ADDRESS=Gh9ZwEmdLJ8DscKNTkTqPbNwLNNB6k64N9B6KF9LA3NA
AMOUNT=1000000
RPC_ENDPOINT=https://rpc.helius.xyz/?api-key=your_helius_api_key
VAULT_URL=https://your-vault-instance.com
VAULT_TOKEN=your_vault_token

#Multi-Destination SPL Token Transfer (token-multi):

TRANSACTION_TYPE=token-multi
DESTINATIONS=address1:1000000,address2:2000000
MINT_ADDRESS=Gh9ZwEmdLJ8DscKNTkTqPbNwLNNB6k64N9B6KF9LA3NA
RPC_ENDPOINT=https://rpc.helius.xyz/?api-key=your_helius_api_key
VAULT_URL=https://your-vault-instance.com
VAULT_TOKEN=your_vault_token

Replace your_helius_api_key with your Helius API key from helius.dev.
Replace your-vault-instance.com with your DQ Vault URL.
Replace your_vault_token with your Vault token
Use valid Solana addresses for DESTINATION_ADDRESS or DESTINATIONS.
Leave SOURCE_ADDRESS and MNEMONIC empty to generate new ones

#run the program: go run main.go
