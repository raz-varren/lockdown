package v1

import (
	"bytes"
	"github.com/raz-varren/lockdown/ld/ldtools"
)

var (
	// Cost profiles
	CostNormal = CostParams{
		Time:    defCostTime,
		Memory:  defCostMem,
		Threads: defCostThread,
	}

	CostSlow = CostParams{
		Time:    defCostTime * 2,
		Memory:  defCostMem,
		Threads: defCostThread + (defCostThread / 2),
	}

	CostFast = CostParams{
		Time:    defCostTime / 2,
		Memory:  defCostMem,
		Threads: defCostThread,
	}
)

type CostParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

type costParams struct {
	time    uint32
	memory  uint32
	threads uint8
}

func (cp *costParams) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(nil)
	buf.Write(ldtools.U32tob(cp.time))
	buf.Write(ldtools.U32tob(cp.memory))
	buf.Write(ldtools.U8tob(cp.threads))
	return buf.Bytes(), nil
}

func (cp *costParams) UnmarshalBinary(data []byte) error {
	if len(data) < cp.Len() {
		panic("data length is too small to be a set of cost params")
	}

	lTime := cp.LenTime()
	lMem := lTime + cp.LenMem()
	lThread := lMem + cp.LenThread()

	cp.time = ldtools.Btou32(data[:lTime])
	cp.memory = ldtools.Btou32(data[lTime:lMem])
	cp.threads = ldtools.Btou8(data[lMem:lThread])

	return nil
}

// Len is the size of all cost params in bytes
func (cp *costParams) Len() int {
	return cp.LenTime() + cp.LenMem() + cp.LenThread()
}

// LenTime is the size of the time cost param in bytes
func (cp *costParams) LenTime() int {
	return lenCostTime
}

// LenMem is the size of the memory cost param in bytes
func (cp *costParams) LenMem() int {
	return lenCostMem
}

// LenThread is the size of the threads cost param in bytes
func (cp *costParams) LenThread() int {
	return lenCostThread
}

// Time returns the time cost param
func (cp *costParams) Time() uint32 {
	return cp.time
}

// Memory returns the memory cost param
func (cp *costParams) Memory() uint32 {
	return cp.memory
}

// Threads returns the threads cost param
func (cp *costParams) Threads() uint8 {
	return cp.threads
}
