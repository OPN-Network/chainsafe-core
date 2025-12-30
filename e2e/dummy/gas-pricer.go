package dummy

import (
	"math/big"

	"github.com/OPN-Network/chainsafe-core/chains/evm/calls/evmgaspricer"
)

type GasPricer interface {
	GasPrice(priority *uint8) ([]*big.Int, error)
}

type StaticGasPriceDeterminant struct {
	client evmgaspricer.GasPriceClient
	opts   *evmgaspricer.GasPricerOpts
}

func NewStaticGasPriceDeterminant(client evmgaspricer.GasPriceClient, opts *evmgaspricer.GasPricerOpts) *StaticGasPriceDeterminant {
	return &StaticGasPriceDeterminant{client: client, opts: opts}
}

func (gasPricer *StaticGasPriceDeterminant) GasPrice(priority *uint8) ([]*big.Int, error) {
	var gasPrice []*big.Int
	switch *priority {
	// medium
	case 1:
		gasPrice = []*big.Int{big.NewInt(80000000000)}
	// fast
	case 2:
		gasPrice = []*big.Int{big.NewInt(140000000000)}
	// slow
	default:
		gasPrice = []*big.Int{big.NewInt(50000000000)}
	}
	return gasPrice, nil
}
