package riscv

import (
	"errors"
	"fmt"
)

// CPU holds the full state of the RISC-V RV32I machine.
type CPU struct {
	PC   uint32
	Regs [32]uint32
	Mem  []byte
}

// ErrHalt is returned when the CPU executes ecall/ebreak.
var ErrHalt = errors.New("halt")

// New creates a CPU with the given memory image loaded.
func New(mem []byte) *CPU {
	c := &CPU{Mem: make([]byte, len(mem))}
	copy(c.Mem, mem)
	return c
}

// ReadReg returns the value of register index i.
// x0 always returns 0.
func (c *CPU) ReadReg(i uint32) uint32 {
	if i == 0 {
		return 0
	}
	return c.Regs[i]
}

// WriteReg sets register index i to val.
// Writes to x0 are ignored.
func (c *CPU) WriteReg(i uint32, val uint32) {
	if i != 0 {
		c.Regs[i] = val
	}
}

// ReadMem32 reads a 32-bit little-endian word from the given address.
func (c *CPU) ReadMem32(addr uint32) uint32

// ReadMem16 reads a 16-bit little-endian value from the given address.
func (c *CPU) ReadMem16(addr uint32) uint16

// ReadMem8 reads a byte from the given address.
func (c *CPU) ReadMem8(addr uint32) uint8

// WriteMem32 writes a 32-bit little-endian word to the given address.
func (c *CPU) WriteMem32(addr uint32, val uint32)

// WriteMem16 writes a 16-bit value to the given address.
func (c *CPU) WriteMem16(addr uint32, val uint16)

// WriteMem8 writes a byte to the given address.
func (c *CPU) WriteMem8(addr uint32, val uint8)

// Step fetches, decodes, and executes one instruction. Returns an error
// if the instruction is illegal or the CPU halts (ecall/ebreak).
func (c *CPU) Step() error {
	instr := c.ReadMem32(c.PC) // 1. fetch
	opcode := instr & 0x7F     // 2. opcode is bits [6:0]

	switch opcode {
	case OpcodeRType:
		c.execRType(instr)
	case OpcodeIArith:
		c.execIArith(instr)
	case OpcodeLoad:
		c.execLoad(instr)
	case OpcodeStore:
		c.execStore(instr)
	case OpcodeBranch:
		c.execBranch(instr)
	case OpcodeJAL:
		c.execJAL(instr)
	case OpcodeJALR:
		c.execJALR(instr)
	case OpcodeLUI:
		c.execLUI(instr)
	case OpcodeAUIPC:
		c.execAUIPC(instr)
	case OpcodeSystem:
		c.execSystem(instr)
	default:
		return fmt.Errorf("illegal opcode 0x%02x at PC=0x%08x", opcode, c.PC)

	}
	return nil
}

// Run executes instructions until an error or halt.
func (c *CPU) Run() error {
	for {
		if err := c.Step(); err != nil {
			return err
		}
	}
}
