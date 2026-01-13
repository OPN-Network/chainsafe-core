package executor

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/OPN-Network/chainsafe-core/chains/evm/executor/proposal"
	"github.com/OPN-Network/chainsafe-core/relayer/message"
	"github.com/OPN-Network/chainsafe-core/types"
	"github.com/rs/zerolog/log"
)

type HandlerMatcher interface {
	GetHandlerAddressForResourceID(resourceID types.ResourceID) (common.Address, error)
	ContractAddress() *common.Address
}

type MessageHandlerFunc func(m *message.Message, handlerAddr, bridgeAddress common.Address) (*proposal.Proposal, error)

// NewEVMMessageHandler creates an instance of EVMMessageHandler that contains
// message handler functions for converting deposit message into a chain specific
// proposal
func NewEVMMessageHandler(handlerMatcher HandlerMatcher) *EVMMessageHandler {
	return &EVMMessageHandler{
		handlerMatcher: handlerMatcher,
	}
}

type EVMMessageHandler struct {
	handlerMatcher HandlerMatcher
	handlers       map[common.Address]MessageHandlerFunc
}

func (mh *EVMMessageHandler) HandleMessage(m *message.Message) (*proposal.Proposal, error) {
	// Matching resource ID with handler.
	addr, err := mh.handlerMatcher.GetHandlerAddressForResourceID(m.ResourceId)
	if err != nil {
		return nil, err
	}
	// Based on handler that registered on BridgeContract
	handleMessage, err := mh.MatchAddressWithHandlerFunc(addr)
	if err != nil {
		return nil, err
	}
	log.Info().Str("type", string(m.Type)).Uint8("src", m.Source).Uint8("dst", m.Destination).Uint64("nonce", m.DepositNonce).Str("resourceID", fmt.Sprintf("%x", m.ResourceId)).Msg("Handling new message")
	prop, err := handleMessage(m, addr, *mh.handlerMatcher.ContractAddress())
	if err != nil {
		return nil, err
	}
	return prop, nil
}

func (mh *EVMMessageHandler) MatchAddressWithHandlerFunc(addr common.Address) (MessageHandlerFunc, error) {
	h, ok := mh.handlers[addr]
	if !ok {
		return nil, fmt.Errorf("no corresponding message handler for this address %s exists", addr.Hex())
	}
	return h, nil
}

// RegisterEventHandler registers an message handler by associating a handler function to a specified address
func (mh *EVMMessageHandler) RegisterMessageHandler(address string, handler MessageHandlerFunc) {
	if address == "" {
		return
	}
	if mh.handlers == nil {
		mh.handlers = make(map[common.Address]MessageHandlerFunc)
	}

	log.Info().Msgf("Registered message handler for address %s", address)

	mh.handlers[common.HexToAddress(address)] = handler
}

func ERC20MessageHandler(m *message.Message, handlerAddr, bridgeAddress common.Address) (*proposal.Proposal, error) {
	if len(m.Payload) != 2 {
		return nil, errors.New("malformed payload. Len  of payload should be 2")
	}
	amount, ok := m.Payload[0].([]byte)
	amountInt := new(big.Int).SetBytes(amount)
	fmt.Printf("\n[ERC20MessageHandler] Source Chain ID: %d, Destination Chain ID: %d\n", m.Source, m.Destination)
	fmt.Printf("Resource ID: %x\n", m.ResourceId)
	fmt.Printf("Amount (bytes): %+v\n", amount)
	fmt.Printf("Amount (int): %s\n", amountInt.String())

	// Resource IDs to match (as hex string, lowercase)
	targetResourceIDs := map[string]bool{
		"611f1b068afe8c257c6008f7f509c9fa3cc488cafbe968dc10588818abfeb435": true,
		"a334bd6d4e65a0ab57b2aac114df09e2831be92397ffffa7a12710ce40bca2ad": true,
	}
	resourceIDHex := fmt.Sprintf("%x", m.ResourceId)
	// 18 -> 6 decimals
	if m.Source == 3 && m.Destination == 1 && targetResourceIDs[resourceIDHex] {
		fmt.Println("[ERC20MessageHandler] Normalizing amount from 18 to 6 decimals")
		factor := new(big.Int).Exp(big.NewInt(10), big.NewInt(12), nil) // 10^12
		amountInt = new(big.Int).Div(amountInt, factor)
		amount = amountInt.Bytes()
		fmt.Printf("Normalized Amount (int): %s\n", amountInt.String())
	}
	// 6 -> 18 decimals
	if m.Source == 1 && m.Destination == 3 && targetResourceIDs[resourceIDHex] {
		fmt.Println("[ERC20MessageHandler] Normalizing amount from 6 to 18 decimals")
		factor := new(big.Int).Exp(big.NewInt(10), big.NewInt(12), nil) // 10^12
		amountInt = new(big.Int).Mul(amountInt, factor)
		amount = amountInt.Bytes()
		fmt.Printf("Normalized Amount (int): %s\n", amountInt.String())
	}
	if !ok {
		return nil, errors.New("wrong payload amount format")
	}
	recipient, ok := m.Payload[1].([]byte)
	if !ok {
		return nil, errors.New("wrong payload recipient format")
	}
	var data []byte
	data = append(data, common.LeftPadBytes(amount, 32)...) // amount (uint256)
	recipientLen := big.NewInt(int64(len(recipient))).Bytes()
	data = append(data, common.LeftPadBytes(recipientLen, 32)...) // length of recipient (uint256)
	data = append(data, recipient...)                             // recipient ([]byte)
	return proposal.NewProposal(m.Source, m.Destination, m.DepositNonce, m.ResourceId, data, handlerAddr, bridgeAddress, m.Metadata), nil
}

func ERC721MessageHandler(msg *message.Message, handlerAddr, bridgeAddress common.Address) (*proposal.Proposal, error) {

	if len(msg.Payload) != 3 {
		return nil, errors.New("malformed payload. Len  of payload should be 3")
	}
	tokenID, ok := msg.Payload[0].([]byte)
	if !ok {
		return nil, errors.New("wrong payload tokenID format")
	}
	recipient, ok := msg.Payload[1].([]byte)
	if !ok {
		return nil, errors.New("wrong payload recipient format")
	}
	metadata, ok := msg.Payload[2].([]byte)
	if !ok {
		return nil, errors.New("wrong payload metadata format")
	}
	data := bytes.Buffer{}
	data.Write(common.LeftPadBytes(tokenID, 32))
	recipientLen := big.NewInt(int64(len(recipient))).Bytes()
	data.Write(common.LeftPadBytes(recipientLen, 32))
	data.Write(recipient)
	metadataLen := big.NewInt(int64(len(metadata))).Bytes()
	data.Write(common.LeftPadBytes(metadataLen, 32))
	data.Write(metadata)
	return proposal.NewProposal(msg.Source, msg.Destination, msg.DepositNonce, msg.ResourceId, data.Bytes(), handlerAddr, bridgeAddress, msg.Metadata), nil
}

func GenericMessageHandler(msg *message.Message, handlerAddr, bridgeAddress common.Address) (*proposal.Proposal, error) {
	if len(msg.Payload) != 1 {
		return nil, errors.New("malformed payload. Len  of payload should be 1")
	}
	metadata, ok := msg.Payload[0].([]byte)
	if !ok {
		return nil, errors.New("wrong payload metadata format")
	}
	data := bytes.Buffer{}
	metadataLen := big.NewInt(int64(len(metadata))).Bytes()
	data.Write(common.LeftPadBytes(metadataLen, 32)) // length of metadata (uint256)
	data.Write(metadata)
	return proposal.NewProposal(msg.Source, msg.Destination, msg.DepositNonce, msg.ResourceId, data.Bytes(), handlerAddr, bridgeAddress, msg.Metadata), nil
}
