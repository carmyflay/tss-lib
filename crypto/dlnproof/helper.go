package dlnproof

import (
	"math/big"

	"github.com/ncw/gmp"
)

func toGMP(x *big.Int) *gmp.Int {
	if x == nil {
		return nil
	}
	return new(gmp.Int).SetBytes(x.Bytes())
}

func toBig(x *gmp.Int) *big.Int {
	if x == nil {
		return nil
	}
	return new(big.Int).SetBytes(x.Bytes())
}
