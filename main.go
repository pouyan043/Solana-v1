package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/anyproto/go-slip10"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/joho/godotenv"
	"github.com/mr-tron/base58"
	"github.com/tyler-smith/go-bip39"
)

const (
	derivationPath     = "m/44'/501'/0'/0'"
	estimatedFee       = uint64(5000)
	defaultTransferAmt = uint64(1_000_000)
)

type Config struct {
	SourceAddress   string
	Mnemonic        string
	TransactionType string
	Destinations    string
	MintAddress     string
	Amount          string
	DestinationAddr string
	RPCEndpoint     string
	VaultURL        string
	VaultToken      string
}

type VaultResponse struct {
	Data map[string]interface{}
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Println(err)
		return
	}
	_, pubKey, err := deriveKeyPair(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	uuid, err := registerWithVault(cfg.VaultURL, cfg.VaultToken, cfg.Mnemonic)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("UUID:", uuid)
	rpcClient := rpc.New(cfg.RPCEndpoint)
	balance, err := getBalance(rpcClient, pubKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Source account balance: %d lamports (%.6f SOL)\n", balance, float64(balance)/1_000_000_000)
	instructions, err := buildInstructions(cfg, rpcClient, pubKey, balance)
	if err != nil {
		fmt.Println(err)
		return
	}
	txSig, signedTxBase58, err := processTransaction(rpcClient, pubKey, instructions, cfg.VaultURL, cfg.VaultToken, uuid, cfg.RPCEndpoint)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Transaction signature:", txSig)
	fmt.Println("Signed transaction (base58):", signedTxBase58)
}

func loadConfig() (Config, error) {
	if err := godotenv.Load(); err != nil {
		return Config{}, fmt.Errorf("loading .env file: %w", err)
	}
	cfg := Config{
		SourceAddress:   os.Getenv("SOURCE_ADDRESS"),
		Mnemonic:        os.Getenv("MNEMONIC"),
		TransactionType: os.Getenv("TRANSACTION_TYPE"),
		Destinations:    os.Getenv("DESTINATIONS"),
		MintAddress:     os.Getenv("MINT_ADDRESS"),
		Amount:          os.Getenv("AMOUNT"),
		DestinationAddr: os.Getenv("DESTINATION_ADDRESS"),
		RPCEndpoint:     os.Getenv("RPC_ENDPOINT"),
		VaultURL:        os.Getenv("VAULT_URL"),
		VaultToken:      os.Getenv("VAULT_TOKEN"),
	}
	if cfg.RPCEndpoint == "" {
		return Config{}, fmt.Errorf("RPC_ENDPOINT is required")
	}
	if cfg.VaultURL == "" {
		return Config{}, fmt.Errorf("VAULT_URL is required")
	}
	if cfg.VaultToken == "" {
		return Config{}, fmt.Errorf("VAULT_TOKEN is required")
	}
	if cfg.TransactionType == "solana-multi" && cfg.Destinations == "" {
		return Config{}, fmt.Errorf("DESTINATIONS is required for solana-multi")
	}
	if cfg.TransactionType == "token-single" && (cfg.Destinations == "" || cfg.MintAddress == "" || cfg.Amount == "") {
		return Config{}, fmt.Errorf("DESTINATIONS, MINT_ADDRESS, and AMOUNT are required for token-single")
	}
	if cfg.TransactionType == "token-multi" && (cfg.Destinations == "" || cfg.MintAddress == "") {
		return Config{}, fmt.Errorf("DESTINATIONS and MINT_ADDRESS are required for token-multi")
	}
	if (cfg.TransactionType == "" || cfg.TransactionType == "solana-single") && cfg.DestinationAddr == "" {
		return Config{}, fmt.Errorf("DESTINATION_ADDRESS is required for solana-single or default transfer")
	}
	return cfg, nil
}

func deriveKeyPair(cfg Config) (solana.PrivateKey, solana.PublicKey, error) {
	var privKey solana.PrivateKey
	var pubKey solana.PublicKey
	if cfg.SourceAddress != "" && cfg.Mnemonic != "" {
		seed := bip39.NewSeed(cfg.Mnemonic, "")
		node, err := slip10.DeriveForPath(derivationPath, seed)
		if err != nil {
			return nil, solana.PublicKey{}, fmt.Errorf("deriving key from mnemonic: %w", err)
		}
		privKeyBytes := node.PrivateKey()
		if len(privKeyBytes) != 32 {
			return nil, solana.PublicKey{}, fmt.Errorf("derived private key is not 32 bytes, got %d", len(privKeyBytes))
		}
		edPrivKey := ed25519.NewKeyFromSeed(privKeyBytes)
		privKey = solana.PrivateKey(edPrivKey)
		pubKey = privKey.PublicKey()
		if pubKey.String() != cfg.SourceAddress {
			return nil, solana.PublicKey{}, fmt.Errorf("derived public key does not match SOURCE_ADDRESS")
		}
	} else {
		entropy, err := bip39.NewEntropy(256)
		if err != nil {
			return nil, solana.PublicKey{}, fmt.Errorf("generating entropy: %w", err)
		}
		mnemonic, err := bip39.NewMnemonic(entropy)
		if err != nil {
			return nil, solana.PublicKey{}, fmt.Errorf("generating mnemonic: %w", err)
		}
		seed := bip39.NewSeed(mnemonic, "")
		node, err := slip10.DeriveForPath(derivationPath, seed)
		if err != nil {
			return nil, solana.PublicKey{}, fmt.Errorf("deriving key: %w", err)
		}
		privKeyBytes := node.PrivateKey()
		if len(privKeyBytes) != 32 {
			return nil, solana.PublicKey{}, fmt.Errorf("derived private key is not 32 bytes, got %d", len(privKeyBytes))
		}
		edPrivKey := ed25519.NewKeyFromSeed(privKeyBytes)
		privKey = solana.PrivateKey(edPrivKey)
		pubKey = privKey.PublicKey()
		if err := writeEnvFile(pubKey.String(), mnemonic); err != nil {
			return nil, solana.PublicKey{}, fmt.Errorf("writing .env file: %w", err)
		}
	}
	return privKey, pubKey, nil
}

func getBalance(client *rpc.Client, pubKey solana.PublicKey) (uint64, error) {
	resp, err := client.GetBalance(context.Background(), pubKey, rpc.CommitmentFinalized)
	if err != nil {
		return 0, fmt.Errorf("getting account balance: %w", err)
	}
	return resp.Value, nil
}

func buildInstructions(cfg Config, client *rpc.Client, pubKey solana.PublicKey, balance uint64) ([]solana.Instruction, error) {
	var limiter int = 10
	var instructions []solana.Instruction
	switch cfg.TransactionType {
	case "solana-multi":
		destAmountPairs := strings.Split(cfg.Destinations, ",")
		var destinations []string
		var amounts []uint64
		for i, pair := range destAmountPairs {
			if i >= limiter {
				return nil, fmt.Errorf("too many destinations: maximum allowed is %d", limiter)
			}
			parts := strings.Split(strings.TrimSpace(pair), ":")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid destination:amount format at index %d: %s", i, pair)
			}
			dest := strings.TrimSpace(parts[0])
			amtStr := strings.TrimSpace(parts[1])
			if dest == "" {
				return nil, fmt.Errorf("destination address at index %d is empty", i)
			}
			if len(dest) < 32 || len(dest) > 44 {
				return nil, fmt.Errorf("destination address at index %d is invalid (length %d, expected ~44 characters): %s", i, len(dest), dest)
			}
			_, err := base58.Decode(dest)
			if err != nil {
				return nil, fmt.Errorf("destination address at index %d is not valid base58: %s, error: %v", i, dest, err)
			}
			amt, err := parseAmount(amtStr)
			if err != nil {
				return nil, fmt.Errorf("parsing amount at index %d: %v", i, err)
			}
			if amt == 0 {
				return nil, fmt.Errorf("amount at index %d is zero", i)
			}
			destinations = append(destinations, dest)
			amounts = append(amounts, amt)
		}
		totalAmount := uint64(0)
		for _, amt := range amounts {
			totalAmount += amt
		}
		if balance < totalAmount+estimatedFee {
			return nil, fmt.Errorf("insufficient balance. Required: %d lamports, Available: %d lamports", totalAmount+estimatedFee, balance)
		}
		for i, dest := range destinations {
			destPubKey, err := solana.PublicKeyFromBase58(dest)
			if err != nil {
				return nil, fmt.Errorf("parsing destination public key at index %d: %v", i, err)
			}
			instruction := system.NewTransferInstruction(amounts[i], pubKey, destPubKey).Build()
			instructions = append(instructions, instruction)
		}
	case "token-single":
		mintPubKey, err := solana.PublicKeyFromBase58(cfg.MintAddress)
		if err != nil {
			return nil, err
		}
		amount, err := parseAmount(cfg.Amount)
		if err != nil {
			return nil, err
		}
		destPubKey, err := solana.PublicKeyFromBase58(cfg.Destinations)
		if err != nil {
			return nil, err
		}
		sourceTokenAccount, _, err := solana.FindAssociatedTokenAddress(pubKey, mintPubKey)
		if err != nil {
			return nil, err
		}
		destTokenAccount, _, err := solana.FindAssociatedTokenAddress(destPubKey, mintPubKey)
		if err != nil {
			return nil, err
		}
		if balance < estimatedFee {
			return nil, fmt.Errorf("insufficient SOL balance. Required: %d lamports, Available: %d lamports", estimatedFee, balance)
		}
		tokenBalanceResp, err := client.GetTokenAccountBalance(context.Background(), sourceTokenAccount, rpc.CommitmentFinalized)
		if err != nil {
			return nil, err
		}
		tokenBalance, err := strconv.ParseUint(tokenBalanceResp.Value.Amount, 10, 64)
		if err != nil {
			return nil, err
		}
		if tokenBalance < amount {
			return nil, fmt.Errorf("insufficient token balance. Required: %d, Available: %d", amount, tokenBalance)
		}
		destAccountInfo, err := client.GetAccountInfo(context.Background(), destTokenAccount)
		if err != nil || destAccountInfo == nil {
			return nil, fmt.Errorf("destination token account does not exist: %s", destTokenAccount)
		}
		instruction := token.NewTransferInstruction(
			amount,
			sourceTokenAccount,
			destTokenAccount,
			pubKey,
			[]solana.PublicKey{},
		).Build()
		instructions = append(instructions, instruction)
	case "token-multi":
		mintPubKey, err := solana.PublicKeyFromBase58(cfg.MintAddress)
		if err != nil {
			return nil, err
		}
		destAmountPairs := strings.Split(cfg.Destinations, ",")
		var destinations []string
		var amounts []uint64
		for i, pair := range destAmountPairs {
			if i >= limiter {
				return nil, fmt.Errorf("too many destinations: maximum allowed is %d", limiter)
			}
			parts := strings.Split(strings.TrimSpace(pair), ":")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid destination:amount format at index %d: %s", i, pair)
			}
			dest := strings.TrimSpace(parts[0])
			amtStr := strings.TrimSpace(parts[1])
			if dest == "" {
				return nil, fmt.Errorf("destination address at index %d is empty", i)
			}
			if len(dest) < 32 || len(dest) > 44 {
				return nil, fmt.Errorf("destination address at index %d is invalid (length %d, expected ~44 characters): %s", i, len(dest), dest)
			}
			_, err := base58.Decode(dest)
			if err != nil {
				return nil, fmt.Errorf("destination address at index %d is not valid base58: %s, error: %v", i, dest, err)
			}
			amt, err := parseAmount(amtStr)
			if err != nil {
				return nil, fmt.Errorf("parsing amount at index %d: %v", i, err)
			}
			if amt == 0 {
				return nil, fmt.Errorf("amount at index %d is zero", i)
			}
			destinations = append(destinations, dest)
			amounts = append(amounts, amt)
		}
		if balance < estimatedFee {
			return nil, fmt.Errorf("insufficient SOL balance. Required: %d lamports, Available: %d lamports", estimatedFee, balance)
		}
		sourceTokenAccount, _, err := solana.FindAssociatedTokenAddress(pubKey, mintPubKey)
		if err != nil {
			return nil, err
		}
		tokenBalanceResp, err := client.GetTokenAccountBalance(context.Background(), sourceTokenAccount, rpc.CommitmentFinalized)
		if err != nil {
			return nil, err
		}
		tokenBalance, err := strconv.ParseUint(tokenBalanceResp.Value.Amount, 10, 64)
		if err != nil {
			return nil, err
		}
		totalTokenAmount := uint64(0)
		for _, amt := range amounts {
			totalTokenAmount += amt
		}
		if tokenBalance < totalTokenAmount {
			return nil, fmt.Errorf("insufficient token balance. Required: %d, Available: %d", totalTokenAmount, tokenBalance)
		}
		for i, dest := range destinations {
			destPubKey, err := solana.PublicKeyFromBase58(dest)
			if err != nil {
				return nil, fmt.Errorf("parsing destination public key at index %d: %v", i, err)
			}
			destTokenAccount, _, err := solana.FindAssociatedTokenAddress(destPubKey, mintPubKey)
			if err != nil {
				return nil, err
			}
			destAccountInfo, err := client.GetAccountInfo(context.Background(), destTokenAccount)
			if err != nil || destAccountInfo == nil {
				return nil, fmt.Errorf("destination token account does not exist: %s", destTokenAccount)
			}
			instruction := token.NewTransferInstruction(
				amounts[i],
				sourceTokenAccount,
				destTokenAccount,
				pubKey,
				[]solana.PublicKey{},
			).Build()
			instructions = append(instructions, instruction)
		}
	case "solana-single", "":
		if len(cfg.DestinationAddr) < 32 || len(cfg.DestinationAddr) > 44 {
			return nil, fmt.Errorf("destination address is invalid (length %d, expected ~44 characters): %s", len(cfg.DestinationAddr), cfg.DestinationAddr)
		}
		_, err := base58.Decode(cfg.DestinationAddr)
		if err != nil {
			return nil, fmt.Errorf("destination address is not valid base58: %s, error: %v", cfg.DestinationAddr, err)
		}
		destPubKey, err := solana.PublicKeyFromBase58(cfg.DestinationAddr)
		if err != nil {
			return nil, err
		}
		// Parse amount from AMOUNT or DESTINATIONS
		var transferAmt uint64
		if cfg.Amount != "" {
			transferAmt, err = parseAmount(cfg.Amount)
			if err != nil {
				return nil, fmt.Errorf("parsing amount: %v", err)
			}
		} else {
			transferAmt = defaultTransferAmt // Fallback to default
		}
		if balance < transferAmt+estimatedFee {
			return nil, fmt.Errorf("insufficient balance. Required: %d lamports, Available: %d lamports", transferAmt+estimatedFee, balance)
		}
		instruction := system.NewTransferInstruction(transferAmt, pubKey, destPubKey).Build()
		instructions = append(instructions, instruction)
	}
	return instructions, nil
}

func processTransaction(client *rpc.Client, pubKey solana.PublicKey, instructions []solana.Instruction, vaultURL, vaultToken, uuid, rpcEndpoint string) (string, string, error) {
	resp, err := client.GetLatestBlockhash(context.Background(), rpc.CommitmentFinalized)
	if err != nil {
		return "", "", err
	}
	blockhash := resp.Value.Blockhash
	if resp.Value.LastValidBlockHeight == 0 {
		return "", "", fmt.Errorf("received invalid blockhash")
	}
	tx, err := solana.NewTransaction(instructions, blockhash, solana.TransactionPayer(pubKey))
	if err != nil {
		return "", "", err
	}
	txBytes, err := tx.MarshalBinary()
	if err != nil {
		return "", "", err
	}
	payloadHex := hex.EncodeToString(txBytes)
	signedTxBase64, err := signWithVault(vaultURL, vaultToken, uuid, derivationPath, payloadHex)
	if err != nil {
		return "", "", err
	}
	signedTxBytes, err := base64.StdEncoding.DecodeString(signedTxBase64)
	if err != nil {
		return "", "", err
	}
	signedTx, err := solana.TransactionFromBytes(signedTxBytes)
	if err != nil {
		return "", "", err
	}
	messageBytes, err := signedTx.Message.MarshalBinary()
	if err != nil {
		return "", "", err
	}
	if len(signedTx.Signatures) < 1 {
		return "", "", fmt.Errorf("no signatures in signed transaction")
	}
	sig := signedTx.Signatures[0]
	if !ed25519.Verify(pubKey[:], messageBytes, sig[:]) {
		return "", "", fmt.Errorf("signature verification failed")
	}
	txBase58 := base58.Encode(signedTxBytes)
	txSig, err := sendTransactionJSONRPC(rpcEndpoint, txBase58)
	if err != nil {
		return "", "", err
	}
	return txSig, txBase58, nil
}

func parseAmount(amountStr string) (uint64, error) {
	return strconv.ParseUint(amountStr, 10, 64)
}

func sendTransactionJSONRPC(rpcEndpoint, txBase58 string) (string, error) {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "sendTransaction",
		"params":  []interface{}{txBase58},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", rpcEndpoint, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected JSON-RPC status code: %d, body: %s", resp.StatusCode, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if errField, ok := result["error"]; ok {
		return "", fmt.Errorf("JSON-RPC error response: %v", errField)
	}
	txSig, ok := result["result"].(string)
	if !ok {
		return "", fmt.Errorf("invalid JSON-RPC response format: result field missing or not a string")
	}
	return txSig, nil
}

func registerWithVault(vaultURL, vaultToken, mnemonic string) (string, error) {
	url := vaultURL + "/v1/dq/register"
	payload := map[string]string{
		"username": "root",
		"mnemonic": mnemonic,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", vaultToken)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}
	var result VaultResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	returnedUUID, ok := result.Data["uuid"].(string)
	if !ok {
		return "", fmt.Errorf("invalid response format: uuid field missing or not a string")
	}
	return returnedUUID, nil
}

func signWithVault(vaultURL, vaultToken, uuid, path, payloadHex string) (string, error) {
	url := vaultURL + "/v1/dq/signature"
	signReq := map[string]interface{}{
		"uuid":     uuid,
		"path":     path,
		"payload":  payloadHex,
		"coinType": 501,
	}
	jsonSignReq, err := json.Marshal(signReq)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonSignReq))
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", vaultToken)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}
	var signResp VaultResponse
	if err := json.Unmarshal(body, &signResp); err != nil {
		return "", err
	}
	signature, ok := signResp.Data["signature"].(string)
	if !ok {
		return "", fmt.Errorf("invalid response format: signature field missing or not a string")
	}
	return signature, nil
}

func writeEnvFile(sourceAddress, mnemonic string) error {
	envMap, err := godotenv.Read()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if envMap == nil {
		envMap = make(map[string]string)
	}
	envMap["SOURCE_ADDRESS"] = sourceAddress
	envMap["MNEMONIC"] = mnemonic
	var envContent strings.Builder
	for key, value := range envMap {
		if value != "" {
			envContent.WriteString(fmt.Sprintf("%s=%s\n", key, value))
		}
	}
	return os.WriteFile(".env", []byte(envContent.String()), 0600)
}
