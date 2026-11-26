package x86emu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

var tscEpoch = time.Now()

const (
	regEAX = 0
	regECX = 1
	regEDX = 2
	regEBX = 3
	regESP = 4
	regEBP = 5
	regESI = 6
	regEDI = 7
)

var ErrExitThread = errors.New("x86emu: thread exited")

// CPU 为纯 Go 32 位 x86 + SSE2 解释器核心
type CPU struct {
	R         [8]uint32
	EIP       uint32
	EFLAGS    uint32
	XMM       [8][16]byte
	MXCSR     uint32
	FSBase    uint32
	Mem       *Mem
	Steps     uint64
	StepLimit uint64
	HLE       func(id uint32) error
	Exited    bool
	codeStart uint32
	codeEnd   uint32
	icache    []decInsn
}

const (
	DefaultStepLimit uint64 = 100_000_000
	MaxStepLimit     uint64 = 500_000_000
)

func NewCPU(mem *Mem, hle func(id uint32) error) *CPU {
	c := &CPU{
		EFLAGS:    0x00000202,
		MXCSR:     0x1F80,
		FSBase:    TEBAddr,
		Mem:       mem,
		StepLimit: DefaultStepLimit,
		HLE:       hle,
	}
	c.R[regESP] = InitESP
	return c
}

func (c *CPU) fetch8() (byte, error) {
	b, err := c.Mem.Read8(c.EIP)
	if err != nil {
		return 0, err
	}
	c.EIP++
	return b, nil
}

func (c *CPU) fetch16() (uint16, error) {
	v, err := c.Mem.Read16(c.EIP)
	if err != nil {
		return 0, err
	}
	c.EIP += 2
	return v, nil
}

func (c *CPU) fetch32() (uint32, error) {
	v, err := c.Mem.Read32(c.EIP)
	if err != nil {
		return 0, err
	}
	c.EIP += 4
	return v, nil
}

func (c *CPU) getReg(idx byte, bits uint) uint32 {
	idx &= 7
	switch bits {
	case 8:
		if idx < 4 {
			return c.R[idx] & 0xFF
		}
		return (c.R[idx-4] >> 8) & 0xFF
	case 16:
		return c.R[idx] & 0xFFFF
	default:
		return c.R[idx]
	}
}

func (c *CPU) setReg(idx byte, bits uint, val uint32) {
	idx &= 7
	switch bits {
	case 8:
		if idx < 4 {
			c.R[idx] = (c.R[idx] &^ 0xFF) | (val & 0xFF)
		} else {
			r := idx - 4
			c.R[r] = (c.R[r] &^ 0xFF00) | ((val & 0xFF) << 8)
		}
	case 16:
		c.R[idx] = (c.R[idx] &^ 0xFFFF) | (val & 0xFFFF)
	default:
		c.R[idx] = val
	}
}

func (c *CPU) readSized(addr uint32, bits uint) (uint32, error) {
	switch bits {
	case 8:
		v, err := c.Mem.Read8(addr)
		return uint32(v), err
	case 16:
		v, err := c.Mem.Read16(addr)
		return uint32(v), err
	default:
		return c.Mem.Read32(addr)
	}
}

func (c *CPU) writeSized(addr uint32, bits uint, val uint32) error {
	switch bits {
	case 8:
		return c.Mem.Write8(addr, byte(val))
	case 16:
		return c.Mem.Write16(addr, uint16(val))
	default:
		return c.Mem.Write32(addr, val)
	}
}

func (c *CPU) Push32(v uint32) error {
	c.R[regESP] -= 4
	return c.Mem.Write32(c.R[regESP], v)
}

func (c *CPU) Pop32() (uint32, error) {
	v, err := c.Mem.Read32(c.R[regESP])
	if err != nil {
		return 0, err
	}
	c.R[regESP] += 4
	return v, nil
}

func (c *CPU) push16(v uint16) error {
	c.R[regESP] -= 2
	return c.Mem.Write16(c.R[regESP], v)
}

func (c *CPU) pop16() (uint16, error) {
	v, err := c.Mem.Read16(c.R[regESP])
	if err != nil {
		return 0, err
	}
	c.R[regESP] += 2
	return v, nil
}

func (c *CPU) pushOp(bits uint, v uint32) error {
	if bits == 16 {
		return c.push16(uint16(v))
	}
	return c.Push32(v)
}

func (c *CPU) popOp(bits uint) (uint32, error) {
	if bits == 16 {
		v, err := c.pop16()
		return uint32(v), err
	}
	return c.Pop32()
}

type modrm struct {
	isReg bool
	reg   byte
	rm    byte
	ea    uint32
}

func (c *CPU) decodeModRM(segFS bool) (modrm, error) {
	b, err := c.fetch8()
	if err != nil {
		return modrm{}, err
	}
	mod := (b >> 6) & 3
	reg := (b >> 3) & 7
	rm := b & 7
	if mod == 3 {
		return modrm{isReg: true, reg: reg, rm: rm}, nil
	}
	var ea uint32
	if rm == 4 {
		sib, err := c.fetch8()
		if err != nil {
			return modrm{}, err
		}
		scale := uint32(1) << (sib >> 6)
		index := (sib >> 3) & 7
		base := sib & 7
		if base == 5 && mod == 0 {
			d, err := c.fetch32()
			if err != nil {
				return modrm{}, err
			}
			ea = d
		} else {
			ea = c.R[base]
		}
		if index != 4 {
			ea += c.R[index] * scale
		}
	} else if mod == 0 && rm == 5 {
		d, err := c.fetch32()
		if err != nil {
			return modrm{}, err
		}
		ea = d
	} else {
		ea = c.R[rm]
	}

	switch mod {
	case 1:
		d, err := c.fetch8()
		if err != nil {
			return modrm{}, err
		}
		ea += uint32(int32(int8(d)))
	case 2:
		d, err := c.fetch32()
		if err != nil {
			return modrm{}, err
		}
		ea += d
	}
	if segFS {
		ea += c.FSBase
	}
	return modrm{isReg: false, reg: reg, rm: rm, ea: ea}, nil
}

func (c *CPU) readRM(m modrm, bits uint) (uint32, error) {
	if m.isReg {
		return c.getReg(m.rm, bits), nil
	}
	return c.readSized(m.ea, bits)
}

func (c *CPU) writeRM(m modrm, bits uint, val uint32) error {
	if m.isReg {
		c.setReg(m.rm, bits, val)
		return nil
	}
	return c.writeSized(m.ea, bits, val)
}

func (c *CPU) readXMM(m modrm, n uint32) ([16]byte, error) {
	var out [16]byte
	if m.isReg {
		return c.XMM[m.rm], nil
	}
	b, err := c.Mem.ReadBytes(m.ea, n)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

func (c *CPU) writeXMM(m modrm, n uint32, v [16]byte) error {
	if m.isReg {
		copy(c.XMM[m.rm][:n], v[:n])
		return nil
	}
	return c.Mem.WriteBytes(m.ea, v[:n])
}

func (c *CPU) fetchImm(bits uint) (uint32, error) {
	switch bits {
	case 8:
		v, err := c.fetch8()
		return uint32(v), err
	case 16:
		v, err := c.fetch16()
		return uint32(v), err
	default:
		return c.fetch32()
	}
}

func (c *CPU) aluOp(op byte, a, b uint32, bits uint) (uint32, bool) {
	switch op {
	case 0: // ADD
		res, nf := aluAdd(a, b, 0, c.EFLAGS, bits)
		c.EFLAGS = nf
		return res, true
	case 1: // OR
		res := (a | b) & widthMask(bits)
		c.EFLAGS = aluLogic(res, c.EFLAGS, bits)
		return res, true
	case 2: // ADC
		res, nf := aluAdd(a, b, c.EFLAGS&flagCF, c.EFLAGS, bits)
		c.EFLAGS = nf
		return res, true
	case 3: // SBB
		res, nf := aluSub(a, b, c.EFLAGS&flagCF, c.EFLAGS, bits)
		c.EFLAGS = nf
		return res, true
	case 4: // AND
		res := (a & b) & widthMask(bits)
		c.EFLAGS = aluLogic(res, c.EFLAGS, bits)
		return res, true
	case 5: // SUB
		res, nf := aluSub(a, b, 0, c.EFLAGS, bits)
		c.EFLAGS = nf
		return res, true
	case 6: // XOR
		res := (a ^ b) & widthMask(bits)
		c.EFLAGS = aluLogic(res, c.EFLAGS, bits)
		return res, true
	case 7: // CMP
		_, nf := aluSub(a, b, 0, c.EFLAGS, bits)
		c.EFLAGS = nf
		return 0, false
	}
	return a, false
}

func (c *CPU) enterCall(target uint32) error {
	if target >= StubBase && target < StubBase+StubSize {
		id := (target - StubBase) / 4
		if c.HLE == nil {
			return fmt.Errorf("HLE call to stub #%d @0x%08x without handler", id, target)
		}
		return c.HLE(id)
	}
	c.EIP = target
	return nil
}

// Call 在虚拟机中执行指定 32 位函数，直到返回到 HaltAddr
func (c *CPU) Call(fnAddr uint32, args ...uint32) (uint32, error) {
	savedESP := c.R[regESP]
	for i := len(args) - 1; i >= 0; i-- {
		if err := c.Push32(args[i]); err != nil {
			c.R[regESP] = savedESP
			return 0, err
		}
	}
	if err := c.Push32(HaltAddr); err != nil {
		c.R[regESP] = savedESP
		return 0, err
	}
	c.EIP = fnAddr
	if c.icache != nil {
		err := c.runLoopFast()
		c.R[regESP] = savedESP
		if err != nil {
			return c.R[regEAX], err
		}
		return c.R[regEAX], nil
	}
	for c.EIP != HaltAddr {
		if c.Exited {
			c.R[regESP] = savedESP
			return c.R[regEAX], ErrExitThread
		}
		if c.Steps >= c.StepLimit {
			c.R[regESP] = savedESP
			return 0, fmt.Errorf("x86emu step limit exceeded (%d) @EIP=0x%08x", c.Steps, c.EIP)
		}
		if err := c.step(); err != nil {
			if errors.Is(err, ErrExitThread) {
				c.R[regESP] = savedESP
				return c.R[regEAX], ErrExitThread
			}
			c.R[regESP] = savedESP
			return 0, fmt.Errorf("@EIP=0x%08x (step=%d): %w", c.EIP, c.Steps, err)
		}
	}
	c.R[regESP] = savedESP
	return c.R[regEAX], nil
}

func (c *CPU) step() error {
	c.Steps++
	if c.EIP >= StubBase && c.EIP < StubBase+StubSize {
		return c.enterCall(c.EIP)
	}
	insnStart := c.EIP

	var has66, has67, hasF2, hasF3, segFS bool
	for p := 0; p < 6; p++ {
		op, err := c.fetch8()
		if err != nil {
			return err
		}
		switch op {
		case 0x66:
			has66 = true
			continue
		case 0x67:
			has67 = true
			continue
		case 0xF2:
			hasF2 = true
			continue
		case 0xF3:
			hasF3 = true
			continue
		case 0xF0: // LOCK
			continue
		case 0x64:
			segFS = true
			continue
		case 0x26, 0x2E, 0x36, 0x3E, 0x65: // other segment overrides
			continue
		}
		_ = has67
		return c.execOpcode(insnStart, op, has66, hasF2, hasF3, segFS)
	}
	return fmt.Errorf("too many prefixes @0x%08x", insnStart)
}

func opBits(byteOp bool, has66 bool) uint {
	if byteOp {
		return 8
	}
	if has66 {
		return 16
	}
	return 32
}

func (c *CPU) execOpcode(insnStart uint32, op byte, has66, hasF2, hasF3, segFS bool) error {
	bits := opBits(false, has66)

	// 00..3F: 标准 ALU (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP) + DAA/DAS/AAA/AAS/seg 已跳过
	if op < 0x40 && (op&7) <= 5 {
		aluKind := (op >> 3) & 7
		sub := op & 7
		b := opBits((sub&1) == 0, has66)
		switch sub {
		case 0, 1: // r/m, r
			m, err := c.decodeModRM(segFS)
			if err != nil {
				return err
			}
			dst, err := c.readRM(m, b)
			if err != nil {
				return err
			}
			src := c.getReg(m.reg, b)
			if res, wr := c.aluOp(aluKind, dst, src, b); wr {
				return c.writeRM(m, b, res)
			}
			return nil
		case 2, 3: // r, r/m
			m, err := c.decodeModRM(segFS)
			if err != nil {
				return err
			}
			src, err := c.readRM(m, b)
			if err != nil {
				return err
			}
			dst := c.getReg(m.reg, b)
			if res, wr := c.aluOp(aluKind, dst, src, b); wr {
				c.setReg(m.reg, b, res)
			}
			return nil
		case 4, 5: // AL/EAX, imm
			imm, err := c.fetchImm(b)
			if err != nil {
				return err
			}
			dst := c.getReg(regEAX, b)
			if res, wr := c.aluOp(aluKind, dst, imm, b); wr {
				c.setReg(regEAX, b, res)
			}
			return nil
		}
	}

	switch {
	case op >= 0x40 && op <= 0x47: // INC r
		r := op & 7
		res, nf := aluInc(c.getReg(r, bits), c.EFLAGS, bits)
		c.EFLAGS = nf
		c.setReg(r, bits, res)
		return nil
	case op >= 0x48 && op <= 0x4F: // DEC r
		r := op & 7
		res, nf := aluDec(c.getReg(r, bits), c.EFLAGS, bits)
		c.EFLAGS = nf
		c.setReg(r, bits, res)
		return nil
	case op >= 0x50 && op <= 0x57: // PUSH r
		return c.pushOp(bits, c.getReg(op&7, bits))
	case op >= 0x58 && op <= 0x5F: // POP r
		v, err := c.popOp(bits)
		if err != nil {
			return err
		}
		c.setReg(op&7, bits, v)
		return nil
	case op >= 0x70 && op <= 0x7F: // Jcc rel8
		d, err := c.fetch8()
		if err != nil {
			return err
		}
		if evalCC(c.EFLAGS, op&0xF) {
			c.EIP = uint32(int32(c.EIP) + int32(int8(d)))
		}
		return nil
	case op >= 0x90 && op <= 0x97: // NOP / XCHG EAX, r
		if op == 0x90 {
			return nil
		}
		r := op & 7
		a := c.getReg(regEAX, bits)
		b := c.getReg(r, bits)
		c.setReg(regEAX, bits, b)
		c.setReg(r, bits, a)
		return nil
	case op >= 0xB0 && op <= 0xB7: // MOV r8, imm8
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		c.setReg(op&7, 8, uint32(imm))
		return nil
	case op >= 0xB8 && op <= 0xBF: // MOV r16/32, imm
		imm, err := c.fetchImm(bits)
		if err != nil {
			return err
		}
		c.setReg(op&7, bits, imm)
		return nil
	}

	switch op {
	case 0x0F:
		return c.exec0F(insnStart, has66, hasF2, hasF3, segFS)

	case 0x60: // PUSHAD
		origESP := c.R[regESP]
		for i := 0; i < 8; i++ {
			v := c.R[i]
			if i == regESP {
				v = origESP
			}
			if err := c.Push32(v); err != nil {
				return err
			}
		}
		return nil

	case 0x61: // POPAD
		for i := 7; i >= 0; i-- {
			v, err := c.Pop32()
			if err != nil {
				return err
			}
			if i != regESP {
				c.R[i] = v
			}
		}
		return nil

	case 0x68: // PUSH imm32/imm16
		imm, err := c.fetchImm(bits)
		if err != nil {
			return err
		}
		return c.pushOp(bits, imm)

	case 0x69: // IMUL r, rm, imm
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		v, err := c.readRM(m, bits)
		if err != nil {
			return err
		}
		imm, err := c.fetchImm(bits)
		if err != nil {
			return err
		}
		c.doIMUL(m.reg, v, imm, bits)
		return nil

	case 0x6A: // PUSH imm8 (sign-extended)
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		return c.pushOp(bits, uint32(int32(int8(imm))))

	case 0x6B: // IMUL r, rm, imm8 (sign-extended)
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		v, err := c.readRM(m, bits)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		c.doIMUL(m.reg, v, uint32(int32(int8(imm))), bits)
		return nil

	case 0x80, 0x81, 0x82, 0x83: // Grp1 ALU rm, imm
		b := opBits(op == 0x80 || op == 0x82, has66)
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		var imm uint32
		if op == 0x83 {
			i8, err := c.fetch8()
			if err != nil {
				return err
			}
			imm = uint32(int32(int8(i8))) & widthMask(b)
		} else {
			imm, err = c.fetchImm(b)
			if err != nil {
				return err
			}
		}
		dst, err := c.readRM(m, b)
		if err != nil {
			return err
		}
		if res, wr := c.aluOp(m.reg, dst, imm, b); wr {
			return c.writeRM(m, b, res)
		}
		return nil

	case 0x84, 0x85: // TEST rm, r
		b := opBits(op == 0x84, has66)
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		dst, err := c.readRM(m, b)
		if err != nil {
			return err
		}
		src := c.getReg(m.reg, b)
		c.EFLAGS = aluLogic(dst&src, c.EFLAGS, b)
		return nil

	case 0x86, 0x87: // XCHG rm, r
		b := opBits(op == 0x86, has66)
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		v, err := c.readRM(m, b)
		if err != nil {
			return err
		}
		r := c.getReg(m.reg, b)
		c.setReg(m.reg, b, v)
		return c.writeRM(m, b, r)

	case 0x88, 0x89: // MOV rm, r
		b := opBits(op == 0x88, has66)
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		return c.writeRM(m, b, c.getReg(m.reg, b))

	case 0x8A, 0x8B: // MOV r, rm
		b := opBits(op == 0x8A, has66)
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		v, err := c.readRM(m, b)
		if err != nil {
			return err
		}
		c.setReg(m.reg, b, v)
		return nil

	case 0x8D: // LEA r, m
		m, err := c.decodeModRM(false) // LEA 仅算有效地址偏移，不加段基址
		if err != nil {
			return err
		}
		if m.isReg {
			return fmt.Errorf("LEA with mod==3 @0x%08x", insnStart)
		}
		c.setReg(m.reg, bits, m.ea)
		return nil

	case 0x8F: // POP rm
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		v, err := c.popOp(bits)
		if err != nil {
			return err
		}
		return c.writeRM(m, bits, v)

	case 0x98: // CBW / CWDE
		if has66 {
			c.setReg(regEAX, 16, uint32(int16(int8(c.R[regEAX]))))
		} else {
			c.R[regEAX] = uint32(int32(int16(c.R[regEAX])))
		}
		return nil

	case 0x99: // CWD / CDQ
		if has66 {
			if c.R[regEAX]&0x8000 != 0 {
				c.setReg(regEDX, 16, 0xFFFF)
			} else {
				c.setReg(regEDX, 16, 0)
			}
		} else {
			if c.R[regEAX]&0x80000000 != 0 {
				c.R[regEDX] = 0xFFFFFFFF
			} else {
				c.R[regEDX] = 0
			}
		}
		return nil

	case 0x9C: // PUSHF
		return c.pushOp(bits, c.EFLAGS)
	case 0x9D: // POPF
		v, err := c.popOp(bits)
		if err != nil {
			return err
		}
		if bits == 16 {
			c.EFLAGS = (c.EFLAGS &^ 0xFFFF) | (v & 0xFFFF) | 2
		} else {
			c.EFLAGS = v | 2
		}
		return nil
	case 0x9E: // SAHF
		c.EFLAGS = (c.EFLAGS &^ 0xD5) | ((c.R[regEAX] >> 8) & 0xD5) | 2
		return nil
	case 0x9F: // LAHF
		c.R[regEAX] = (c.R[regEAX] &^ 0xFF00) | ((c.EFLAGS & 0xFF) << 8)
		return nil

	case 0xA0, 0xA1: // MOV AL/EAX, [moffs32]
		b := opBits(op == 0xA0, has66)
		addr, err := c.fetch32()
		if err != nil {
			return err
		}
		if segFS {
			addr += c.FSBase
		}
		v, err := c.readSized(addr, b)
		if err != nil {
			return err
		}
		c.setReg(regEAX, b, v)
		return nil

	case 0xA2, 0xA3: // MOV [moffs32], AL/EAX
		b := opBits(op == 0xA2, has66)
		addr, err := c.fetch32()
		if err != nil {
			return err
		}
		if segFS {
			addr += c.FSBase
		}
		return c.writeSized(addr, b, c.getReg(regEAX, b))

	case 0xA4, 0xA5, 0xA6, 0xA7, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF: // String ops
		return c.execStringOp(op, has66, hasF2, hasF3)

	case 0xA8, 0xA9: // TEST AL/EAX, imm
		b := opBits(op == 0xA8, has66)
		imm, err := c.fetchImm(b)
		if err != nil {
			return err
		}
		c.EFLAGS = aluLogic(c.getReg(regEAX, b)&imm, c.EFLAGS, b)
		return nil

	case 0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3: // Shifts/Rotates
		b := opBits(op == 0xC0 || op == 0xD0 || op == 0xD2, has66)
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		var cnt uint32
		switch op {
		case 0xC0, 0xC1:
			c8, err := c.fetch8()
			if err != nil {
				return err
			}
			cnt = uint32(c8)
		case 0xD0, 0xD1:
			cnt = 1
		case 0xD2, 0xD3:
			cnt = c.R[regECX] & 0xFF
		}
		dst, err := c.readRM(m, b)
		if err != nil {
			return err
		}
		res, nf := aluShift(m.reg, dst, cnt, c.EFLAGS, b)
		c.EFLAGS = nf
		return c.writeRM(m, b, res)

	case 0xC2: // RET imm16
		imm, err := c.fetch16()
		if err != nil {
			return err
		}
		retAddr, err := c.Pop32()
		if err != nil {
			return err
		}
		c.R[regESP] += uint32(imm)
		c.EIP = retAddr
		return nil

	case 0xC3: // RET
		retAddr, err := c.Pop32()
		if err != nil {
			return err
		}
		c.EIP = retAddr
		return nil

	case 0xC6, 0xC7: // MOV rm, imm
		b := opBits(op == 0xC6, has66)
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		imm, err := c.fetchImm(b)
		if err != nil {
			return err
		}
		return c.writeRM(m, b, imm)

	case 0xC9: // LEAVE
		c.R[regESP] = c.R[regEBP]
		ebp, err := c.Pop32()
		if err != nil {
			return err
		}
		c.R[regEBP] = ebp
		return nil

	case 0xCC: // INT3 (MSVC /GS 或调试断点，安全继续/忽略)
		return nil

	case 0xCD: // INT imm8 (e.g. int 0x29 __fastfail)
		vec, err := c.fetch8()
		if err != nil {
			return err
		}
		return fmt.Errorf("int 0x%02x triggered @0x%08x", vec, insnStart)

	case 0xE0, 0xE1, 0xE2, 0xE3: // LOOPNE / LOOPE / LOOP / JECXZ
		d, err := c.fetch8()
		if err != nil {
			return err
		}
		if op == 0xE3 {
			if c.R[regECX] == 0 {
				c.EIP = uint32(int32(c.EIP) + int32(int8(d)))
			}
			return nil
		}
		c.R[regECX]--
		take := c.R[regECX] != 0
		if op == 0xE0 {
			take = take && (c.EFLAGS&flagZF == 0)
		} else if op == 0xE1 {
			take = take && (c.EFLAGS&flagZF != 0)
		}
		if take {
			c.EIP = uint32(int32(c.EIP) + int32(int8(d)))
		}
		return nil

	case 0xE8: // CALL rel32
		rel, err := c.fetch32()
		if err != nil {
			return err
		}
		if err := c.Push32(c.EIP); err != nil {
			return err
		}
		target := uint32(int32(c.EIP) + int32(rel))
		return c.enterCall(target)

	case 0xE9: // JMP rel32
		rel, err := c.fetch32()
		if err != nil {
			return err
		}
		return c.enterCall(uint32(int32(c.EIP) + int32(rel)))

	case 0xEB: // JMP rel8
		d, err := c.fetch8()
		if err != nil {
			return err
		}
		c.EIP = uint32(int32(c.EIP) + int32(int8(d)))
		return nil

	case 0xF5: // CMC
		c.EFLAGS ^= flagCF
		return nil
	case 0xF8: // CLC
		c.EFLAGS &^= flagCF
		return nil
	case 0xF9: // STC
		c.EFLAGS |= flagCF
		return nil
	case 0xFC: // CLD
		c.EFLAGS &^= flagDF
		return nil
	case 0xFD: // STD
		c.EFLAGS |= flagDF
		return nil

	case 0xF6, 0xF7: // Grp3
		return c.execGrp3(op, has66, segFS)

	case 0xFE, 0xFF: // Grp4/5
		return c.execGrp45(insnStart, op, has66, segFS)
	}

	return fmt.Errorf("unsupported opcode 0x%02x @0x%08x", op, insnStart)
}

func (c *CPU) doIMUL(dstReg byte, a, b uint32, bits uint) {
	sa := int64(signExt32(a, bits))
	sb := int64(signExt32(b, bits))
	prod := sa * sb
	res := uint32(prod) & widthMask(bits)
	c.setReg(dstReg, bits, res)
	c.EFLAGS &^= flagCF | flagOF
	if int64(signExt32(res, bits)) != prod {
		c.EFLAGS |= flagCF | flagOF
	}
}

func (c *CPU) execStringOp(op byte, has66, hasF2, hasF3 bool) error {
	b := opBits((op&1) == 0, has66)
	step := uint32(b / 8)
	if c.EFLAGS&flagDF != 0 {
		step = ^step + 1
	}
	rep := hasF2 || hasF3
	cnt := uint32(1)
	if rep {
		cnt = c.R[regECX]
		if cnt == 0 {
			return nil
		}
		if c.EFLAGS&flagDF == 0 {
			switch op {
			case 0xA4, 0xA5: // REP MOVSB/MOVSW/MOVSD 批量拷贝快路径
				total := uint64(cnt) * uint64(step)
				if total <= 1<<24 {
					n := uint32(total)
					src := c.R[regESI]
					dst := c.R[regEDI]
					if !(src < dst && uint64(dst) < uint64(src)+total) {
						sBuf, sOff, ok1 := c.Mem.translate(src, n)
						dBuf, dOff, ok2 := c.Mem.translate(dst, n)
						if ok1 && ok2 {
							copy(dBuf[dOff:dOff+n], sBuf[sOff:sOff+n])
							c.Mem.checkCodeRange(dst, n)
							c.R[regESI] += n
							c.R[regEDI] += n
							c.R[regECX] = 0
							return nil
						}
					}
				}
			case 0xAA: // REP STOSB 批量填充快路径
				if err := c.Mem.Fill(c.R[regEDI], cnt, byte(c.R[regEAX])); err == nil {
					c.R[regEDI] += cnt
					c.R[regECX] = 0
					return nil
				}
			case 0xAB: // REP STOSD 批量填充快路径
				if !has66 && uint64(cnt)*4 <= 1<<24 {
					n := cnt * 4
					dst := c.R[regEDI]
					if dBuf, dOff, ok := c.Mem.translate(dst, n); ok {
						val := c.R[regEAX]
						b0, b1, b2, b3 := byte(val), byte(val>>8), byte(val>>16), byte(val>>24)
						seg := dBuf[dOff : dOff+n]
						for off := uint32(0); off < n; off += 4 {
							seg[off] = b0
							seg[off+1] = b1
							seg[off+2] = b2
							seg[off+3] = b3
						}
						c.Mem.checkCodeRange(dst, n)
						c.R[regEDI] += n
						c.R[regECX] = 0
						return nil
					}
				}
			}
		}
	}
	for cnt > 0 {
		switch op {
		case 0xA4, 0xA5: // MOVS
			v, err := c.readSized(c.R[regESI], b)
			if err != nil {
				return err
			}
			if err := c.writeSized(c.R[regEDI], b, v); err != nil {
				return err
			}
			c.R[regESI] += step
			c.R[regEDI] += step
		case 0xA6, 0xA7: // CMPS
			v1, err := c.readSized(c.R[regESI], b)
			if err != nil {
				return err
			}
			v2, err := c.readSized(c.R[regEDI], b)
			if err != nil {
				return err
			}
			_, nf := aluSub(v1, v2, 0, c.EFLAGS, b)
			c.EFLAGS = nf
			c.R[regESI] += step
			c.R[regEDI] += step
			if rep {
				cnt--
				c.R[regECX] = cnt
				if hasF3 && (c.EFLAGS&flagZF == 0) {
					return nil
				}
				if hasF2 && (c.EFLAGS&flagZF != 0) {
					return nil
				}
				continue
			}
		case 0xAA, 0xAB: // STOS
			if err := c.writeSized(c.R[regEDI], b, c.getReg(regEAX, b)); err != nil {
				return err
			}
			c.R[regEDI] += step
		case 0xAC, 0xAD: // LODS
			v, err := c.readSized(c.R[regESI], b)
			if err != nil {
				return err
			}
			c.setReg(regEAX, b, v)
			c.R[regESI] += step
		case 0xAE, 0xAF: // SCAS
			v2, err := c.readSized(c.R[regEDI], b)
			if err != nil {
				return err
			}
			_, nf := aluSub(c.getReg(regEAX, b), v2, 0, c.EFLAGS, b)
			c.EFLAGS = nf
			c.R[regEDI] += step
			if rep {
				cnt--
				c.R[regECX] = cnt
				if hasF3 && (c.EFLAGS&flagZF == 0) {
					return nil
				}
				if hasF2 && (c.EFLAGS&flagZF != 0) {
					return nil
				}
				continue
			}
		}
		cnt--
		if rep {
			c.R[regECX] = cnt
		}
	}
	return nil
}

func (c *CPU) execGrp3(op byte, has66, segFS bool) error {
	b := opBits(op == 0xF6, has66)
	m, err := c.decodeModRM(segFS)
	if err != nil {
		return err
	}
	val, err := c.readRM(m, b)
	if err != nil {
		return err
	}
	switch m.reg {
	case 0, 1: // TEST rm, imm
		imm, err := c.fetchImm(b)
		if err != nil {
			return err
		}
		c.EFLAGS = aluLogic(val&imm, c.EFLAGS, b)
		return nil
	case 2: // NOT
		return c.writeRM(m, b, (^val)&widthMask(b))
	case 3: // NEG
		res, nf := aluNeg(val, c.EFLAGS, b)
		c.EFLAGS = nf
		return c.writeRM(m, b, res)
	case 4: // MUL
		c.EFLAGS &^= flagCF | flagOF
		switch b {
		case 8:
			prod := (c.R[regEAX] & 0xFF) * (val & 0xFF)
			c.setReg(regEAX, 16, prod)
			if prod&0xFF00 != 0 {
				c.EFLAGS |= flagCF | flagOF
			}
		case 16:
			prod := (c.R[regEAX] & 0xFFFF) * (val & 0xFFFF)
			c.setReg(regEAX, 16, prod&0xFFFF)
			c.setReg(regEDX, 16, prod>>16)
			if prod>>16 != 0 {
				c.EFLAGS |= flagCF | flagOF
			}
		default:
			prod := uint64(c.R[regEAX]) * uint64(val)
			c.R[regEAX] = uint32(prod)
			c.R[regEDX] = uint32(prod >> 32)
			if c.R[regEDX] != 0 {
				c.EFLAGS |= flagCF | flagOF
			}
		}
		return nil
	case 5: // IMUL
		c.EFLAGS &^= flagCF | flagOF
		switch b {
		case 8:
			prod := int16(int8(c.R[regEAX])) * int16(int8(val))
			c.setReg(regEAX, 16, uint32(uint16(prod)))
			if int16(int8(prod)) != prod {
				c.EFLAGS |= flagCF | flagOF
			}
		case 16:
			prod := int32(int16(c.R[regEAX])) * int32(int16(val))
			c.setReg(regEAX, 16, uint32(prod)&0xFFFF)
			c.setReg(regEDX, 16, uint32(prod)>>16)
			if int32(int16(prod)) != prod {
				c.EFLAGS |= flagCF | flagOF
			}
		default:
			prod := int64(int32(c.R[regEAX])) * int64(int32(val))
			c.R[regEAX] = uint32(prod)
			c.R[regEDX] = uint32(uint64(prod) >> 32)
			if int64(int32(prod)) != prod {
				c.EFLAGS |= flagCF | flagOF
			}
		}
		return nil
	case 6: // DIV
		if val == 0 {
			return errors.New("divide by zero (DIV)")
		}
		switch b {
		case 8:
			num := c.R[regEAX] & 0xFFFF
			q := num / val
			r := num % val
			c.setReg(regEAX, 8, q)
			c.setReg(4, 8, r) // AH
		case 16:
			num := ((c.R[regEDX] & 0xFFFF) << 16) | (c.R[regEAX] & 0xFFFF)
			q := num / val
			r := num % val
			c.setReg(regEAX, 16, q)
			c.setReg(regEDX, 16, r)
		default:
			num := (uint64(c.R[regEDX]) << 32) | uint64(c.R[regEAX])
			q := num / uint64(val)
			r := num % uint64(val)
			c.R[regEAX] = uint32(q)
			c.R[regEDX] = uint32(r)
		}
		return nil
	case 7: // IDIV
		if val == 0 {
			return errors.New("divide by zero (IDIV)")
		}
		switch b {
		case 8:
			num := int16(c.R[regEAX])
			d := int16(int8(val))
			c.setReg(regEAX, 8, uint32(uint8(num/d)))
			c.setReg(4, 8, uint32(uint8(num%d)))
		case 16:
			num := int32((c.R[regEDX] << 16) | (c.R[regEAX] & 0xFFFF))
			d := int32(int16(val))
			c.setReg(regEAX, 16, uint32(num/d))
			c.setReg(regEDX, 16, uint32(num%d))
		default:
			num := int64((uint64(c.R[regEDX]) << 32) | uint64(c.R[regEAX]))
			d := int64(int32(val))
			c.R[regEAX] = uint32(num / d)
			c.R[regEDX] = uint32(num % d)
		}
		return nil
	}
	return nil
}

func (c *CPU) execGrp45(insnStart uint32, op byte, has66, segFS bool) error {
	b := opBits(op == 0xFE, has66)
	m, err := c.decodeModRM(segFS)
	if err != nil {
		return err
	}
	switch m.reg {
	case 0: // INC
		v, err := c.readRM(m, b)
		if err != nil {
			return err
		}
		res, nf := aluInc(v, c.EFLAGS, b)
		c.EFLAGS = nf
		return c.writeRM(m, b, res)
	case 1: // DEC
		v, err := c.readRM(m, b)
		if err != nil {
			return err
		}
		res, nf := aluDec(v, c.EFLAGS, b)
		c.EFLAGS = nf
		return c.writeRM(m, b, res)
	case 2: // CALL rm32
		if op == 0xFE {
			return fmt.Errorf("invalid 0xFE /2 @0x%08x", insnStart)
		}
		target, err := c.readRM(m, 32)
		if err != nil {
			return err
		}
		if err := c.Push32(c.EIP); err != nil {
			return err
		}
		return c.enterCall(target)
	case 4: // JMP rm32
		if op == 0xFE {
			return fmt.Errorf("invalid 0xFE /4 @0x%08x", insnStart)
		}
		target, err := c.readRM(m, 32)
		if err != nil {
			return err
		}
		return c.enterCall(target)
	case 6: // PUSH rm
		if op == 0xFE {
			return fmt.Errorf("invalid 0xFE /6 @0x%08x", insnStart)
		}
		v, err := c.readRM(m, b)
		if err != nil {
			return err
		}
		return c.pushOp(b, v)
	}
	return fmt.Errorf("unsupported 0x%02x /%d @0x%08x", op, m.reg, insnStart)
}

func (c *CPU) exec0F(insnStart uint32, has66, hasF2, hasF3, segFS bool) error {
	op2, err := c.fetch8()
	if err != nil {
		return err
	}
	bits := opBits(false, has66)

	switch {
	case op2 >= 0x40 && op2 <= 0x4F: // CMOVcc r, rm
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		v, err := c.readRM(m, bits)
		if err != nil {
			return err
		}
		if evalCC(c.EFLAGS, op2&0xF) {
			c.setReg(m.reg, bits, v)
		}
		return nil

	case op2 >= 0x80 && op2 <= 0x8F: // Jcc rel32
		rel, err := c.fetch32()
		if err != nil {
			return err
		}
		if evalCC(c.EFLAGS, op2&0xF) {
			c.EIP = uint32(int32(c.EIP) + int32(rel))
		}
		return nil

	case op2 >= 0x90 && op2 <= 0x9F: // SETcc rm8
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		return c.writeRM(m, 8, boolU32(evalCC(c.EFLAGS, op2&0xF)))

	case op2 >= 0xC8 && op2 <= 0xCF: // BSWAP r32
		r := op2 & 7
		v := c.R[r]
		c.R[r] = (v >> 24) | ((v >> 8) & 0xFF00) | ((v & 0xFF00) << 8) | (v << 24)
		return nil
	}

	switch op2 {
	case 0x01: // XGETBV (0F 01 D0)
		sub, err := c.fetch8()
		if err != nil {
			return err
		}
		if sub == 0xD0 {
			c.R[regEAX] = 0
			c.R[regEDX] = 0
			return nil
		}
		return fmt.Errorf("unsupported 0F 01 0x%02x @0x%08x", sub, insnStart)

	case 0x1F: // multi-byte NOP
		_, err := c.decodeModRM(segFS)
		return err

	case 0x10, 0x28, 0x6F: // MOVUPS/MOVUPD/MOVAPS/MOVAPD/MOVDQA/MOVDQU xmm, xmm/m128 (and F3 MOVSS / F2 MOVSD)
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		if op2 == 0x10 && hasF3 { // MOVSS (32-bit)
			if m.isReg {
				copy(c.XMM[m.reg][:4], c.XMM[m.rm][:4])
			} else {
				v, err := c.Mem.ReadBytes(m.ea, 4)
				if err != nil {
					return err
				}
				c.XMM[m.reg] = [16]byte{}
				copy(c.XMM[m.reg][:4], v)
			}
			return nil
		}
		if op2 == 0x10 && hasF2 { // MOVSD (64-bit)
			if m.isReg {
				copy(c.XMM[m.reg][:8], c.XMM[m.rm][:8])
			} else {
				v, err := c.Mem.ReadBytes(m.ea, 8)
				if err != nil {
					return err
				}
				c.XMM[m.reg] = [16]byte{}
				copy(c.XMM[m.reg][:8], v)
			}
			return nil
		}
		v, err := c.readXMM(m, 16)
		if err != nil {
			return err
		}
		c.XMM[m.reg] = v
		return nil

	case 0x11, 0x29, 0x7F: // MOVUPS/MOVAPS/MOVDQA/MOVDQU xmm/m128, xmm
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		n := uint32(16)
		if op2 == 0x11 && hasF3 {
			n = 4
		} else if op2 == 0x11 && hasF2 {
			n = 8
		}
		return c.writeXMM(m, n, c.XMM[m.reg])

	case 0x12: // MOVLPD / MOVLPS xmm, m64 (or MOVHLPS reg)
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		if m.isReg {
			copy(c.XMM[m.reg][:8], c.XMM[m.rm][8:16])
			return nil
		}
		b, err := c.Mem.ReadBytes(m.ea, 8)
		if err != nil {
			return err
		}
		copy(c.XMM[m.reg][:8], b)
		return nil

	case 0x13: // MOVLPD / MOVLPS m64, xmm
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		return c.writeXMM(m, 8, c.XMM[m.reg])

	case 0x16: // MOVHPD / MOVHPS xmm, m64
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		if m.isReg {
			copy(c.XMM[m.reg][8:16], c.XMM[m.rm][:8])
			return nil
		}
		b, err := c.Mem.ReadBytes(m.ea, 8)
		if err != nil {
			return err
		}
		copy(c.XMM[m.reg][8:16], b)
		return nil

	case 0x17: // MOVHPD / MOVHPS m64, xmm
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		if m.isReg {
			return fmt.Errorf("MOVHPS reg @0x%08x", insnStart)
		}
		return c.Mem.WriteBytes(m.ea, c.XMM[m.reg][8:16])

	case 0x31: // RDTSC
		tsc := uint64(time.Since(tscEpoch).Nanoseconds())*3 + 0x00000400_00000000 + uint64(c.Steps)*32
		c.R[regEAX] = uint32(tsc)
		c.R[regEDX] = uint32(tsc >> 32)
		return nil

	case 0x38: // SSSE3 0F 38 xx
		op3, err := c.fetch8()
		if err != nil {
			return err
		}
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		if op3 == 0x00 { // PSHUFB
			mask, err := c.readXMM(m, 16)
			if err != nil {
				return err
			}
			var out [16]byte
			for i := 0; i < 16; i++ {
				if mask[i]&0x80 != 0 {
					out[i] = 0
				} else {
					out[i] = c.XMM[m.reg][mask[i]&0x0F]
				}
			}
			c.XMM[m.reg] = out
			return nil
		}
		return fmt.Errorf("unsupported 0F 38 0x%02x @0x%08x", op3, insnStart)

	case 0x57, 0xEF: // XORPS / XORPD / PXOR
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		src, err := c.readXMM(m, 16)
		if err != nil {
			return err
		}
		for i := 0; i < 16; i++ {
			c.XMM[m.reg][i] ^= src[i]
		}
		return nil

	case 0x6E: // MOVD xmm, rm32
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		v, err := c.readRM(m, 32)
		if err != nil {
			return err
		}
		c.XMM[m.reg] = [16]byte{}
		binary.LittleEndian.PutUint32(c.XMM[m.reg][:4], v)
		return nil

	case 0x7E: // MOVD rm32, xmm (or F3 0F 7E MOVQ xmm, xmm/m64)
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		if hasF3 {
			src, err := c.readXMM(m, 8)
			if err != nil {
				return err
			}
			c.XMM[m.reg] = [16]byte{}
			copy(c.XMM[m.reg][:8], src[:8])
			return nil
		}
		v := binary.LittleEndian.Uint32(c.XMM[m.reg][:4])
		return c.writeRM(m, 32, v)

	case 0x70: // PSHUFD / PSHUFLW / PSHUFHW
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		src, err := c.readXMM(m, 16)
		if err != nil {
			return err
		}
		var out [16]byte
		if has66 {
			for i := 0; i < 4; i++ {
				sel := (imm >> (i * 2)) & 3
				copy(out[i*4:i*4+4], src[sel*4:sel*4+4])
			}
		} else if hasF2 {
			out = src
			for i := 0; i < 4; i++ {
				sel := (imm >> (i * 2)) & 3
				copy(out[i*2:i*2+2], src[sel*2:sel*2+2])
			}
		} else if hasF3 {
			out = src
			for i := 0; i < 4; i++ {
				sel := (imm >> (i * 2)) & 3
				copy(out[8+i*2:8+i*2+2], src[8+sel*2:8+sel*2+2])
			}
		}
		c.XMM[m.reg] = out
		return nil

	case 0x71, 0x72, 0x73: // PSRL/PSRA/PSLL/PSRLDQ/PSLLDQ
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		c.execXMMShift(op2, m.reg, m.rm, imm)
		return nil

	case 0x74, 0x75, 0x76: // PCMPEQB / PCMPEQW / PCMPEQD
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		src, err := c.readXMM(m, 16)
		if err != nil {
			return err
		}
		switch op2 {
		case 0x74:
			for i := 0; i < 16; i++ {
				if c.XMM[m.reg][i] == src[i] {
					c.XMM[m.reg][i] = 0xFF
				} else {
					c.XMM[m.reg][i] = 0
				}
			}
		case 0x75:
			for i := 0; i < 16; i += 2 {
				if binary.LittleEndian.Uint16(c.XMM[m.reg][i:]) == binary.LittleEndian.Uint16(src[i:]) {
					binary.LittleEndian.PutUint16(c.XMM[m.reg][i:], 0xFFFF)
				} else {
					binary.LittleEndian.PutUint16(c.XMM[m.reg][i:], 0)
				}
			}
		case 0x76:
			for i := 0; i < 16; i += 4 {
				if binary.LittleEndian.Uint32(c.XMM[m.reg][i:]) == binary.LittleEndian.Uint32(src[i:]) {
					binary.LittleEndian.PutUint32(c.XMM[m.reg][i:], 0xFFFFFFFF)
				} else {
					binary.LittleEndian.PutUint32(c.XMM[m.reg][i:], 0)
				}
			}
		}
		return nil

	case 0xD7: // PMOVMSKB r32, xmm
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		var mask uint32
		for i := 0; i < 16; i++ {
			if c.XMM[m.rm][i]&0x80 != 0 {
				mask |= 1 << i
			}
		}
		c.R[m.reg] = mask
		return nil

	case 0xDB, 0xDF, 0xEB: // PAND / PANDN / POR
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		src, err := c.readXMM(m, 16)
		if err != nil {
			return err
		}
		for i := 0; i < 16; i++ {
			switch op2 {
			case 0xDB:
				c.XMM[m.reg][i] &= src[i]
			case 0xDF:
				c.XMM[m.reg][i] = (^c.XMM[m.reg][i]) & src[i]
			case 0xEB:
				c.XMM[m.reg][i] |= src[i]
			}
		}
		return nil

	case 0xFC, 0xFD, 0xFE, 0xF8, 0xF9, 0xFA: // PADDB/W/D / PSUBB/W/D
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		src, err := c.readXMM(m, 16)
		if err != nil {
			return err
		}
		add := op2 >= 0xFC
		switch op2 {
		case 0xFC, 0xF8:
			for i := 0; i < 16; i++ {
				if add {
					c.XMM[m.reg][i] += src[i]
				} else {
					c.XMM[m.reg][i] -= src[i]
				}
			}
		case 0xFD, 0xF9:
			for i := 0; i < 16; i += 2 {
				a := binary.LittleEndian.Uint16(c.XMM[m.reg][i:])
				b := binary.LittleEndian.Uint16(src[i:])
				if add {
					binary.LittleEndian.PutUint16(c.XMM[m.reg][i:], a+b)
				} else {
					binary.LittleEndian.PutUint16(c.XMM[m.reg][i:], a-b)
				}
			}
		case 0xFE, 0xFA:
			for i := 0; i < 16; i += 4 {
				a := binary.LittleEndian.Uint32(c.XMM[m.reg][i:])
				b := binary.LittleEndian.Uint32(src[i:])
				if add {
					binary.LittleEndian.PutUint32(c.XMM[m.reg][i:], a+b)
				} else {
					binary.LittleEndian.PutUint32(c.XMM[m.reg][i:], a-b)
				}
			}
		}
		return nil

	case 0xA2: // CPUID (声明支持 SSE/SSE2/CMOV，关闭 AVX/AES-NI 以迫使走标准路径)
		leaf := c.R[regEAX]
		switch leaf {
		case 0:
			c.R[regEAX] = 1
			c.R[regEBX] = 0x756E6547 // "Genu"
			c.R[regEDX] = 0x49656E69 // "ineI"
			c.R[regECX] = 0x6C65746E // "ntel"
		case 1:
			c.R[regEAX] = 0x000206A7
			c.R[regEBX] = 0x00010800
			c.R[regECX] = 0x00000201 // SSE3 + SSSE3, 无 AVX/AES-NI
			c.R[regEDX] = (1 << 15) | (1 << 23) | (1 << 25) | (1 << 26) // CMOV + MMX + SSE + SSE2
		default:
			c.R[regEAX], c.R[regEBX], c.R[regECX], c.R[regEDX] = 0, 0, 0, 0
		}
		return nil

	case 0xAE: // LDMXCSR / STMXCSR / FENCE
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		if m.isReg {
			return nil // LFENCE/MFENCE/SFENCE
		}
		if m.reg == 2 {
			v, err := c.Mem.Read32(m.ea)
			if err != nil {
				return err
			}
			c.MXCSR = v
			return nil
		}
		if m.reg == 3 {
			return c.Mem.Write32(m.ea, c.MXCSR)
		}
		return fmt.Errorf("unsupported 0F AE /%d @0x%08x", m.reg, insnStart)

	case 0xAF: // IMUL r, rm
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		src, err := c.readRM(m, bits)
		if err != nil {
			return err
		}
		c.doIMUL(m.reg, c.getReg(m.reg, bits), src, bits)
		return nil

	case 0xA3, 0xAB, 0xB3, 0xBB, 0xBA: // BT / BTS / BTR / BTC
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		var bitIdx uint32
		var kind byte
		if op2 == 0xBA {
			imm, err := c.fetch8()
			if err != nil {
				return err
			}
			bitIdx = uint32(imm) % uint32(bits)
			kind = m.reg
		} else {
			bitIdx = c.getReg(m.reg, bits) % uint32(bits)
			switch op2 {
			case 0xA3:
				kind = 4 // BT
			case 0xAB:
				kind = 5 // BTS
			case 0xB3:
				kind = 6 // BTR
			case 0xBB:
				kind = 7 // BTC
			}
		}
		val, err := c.readRM(m, bits)
		if err != nil {
			return err
		}
		mask := uint32(1) << bitIdx
		c.EFLAGS &^= flagCF
		if val&mask != 0 {
			c.EFLAGS |= flagCF
		}
		switch kind {
		case 5:
			return c.writeRM(m, bits, val|mask)
		case 6:
			return c.writeRM(m, bits, val&^mask)
		case 7:
			return c.writeRM(m, bits, val^mask)
		}
		return nil

	case 0xA4, 0xA5, 0xAC, 0xAD: // SHLD / SHRD
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		var cnt uint32
		if op2 == 0xA4 || op2 == 0xAC {
			imm, err := c.fetch8()
			if err != nil {
				return err
			}
			cnt = uint32(imm)
		} else {
			cnt = c.R[regECX] & 0xFF
		}
		dst, err := c.readRM(m, bits)
		if err != nil {
			return err
		}
		src := c.getReg(m.reg, bits)
		var res, nf uint32
		if op2 == 0xA4 || op2 == 0xA5 {
			res, nf = aluShld(dst, src, cnt, c.EFLAGS, bits)
		} else {
			res, nf = aluShrd(dst, src, cnt, c.EFLAGS, bits)
		}
		c.EFLAGS = nf
		return c.writeRM(m, bits, res)

	case 0xB0, 0xB1: // CMPXCHG rm, r
		b := opBits(op2 == 0xB0, has66)
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		dst, err := c.readRM(m, b)
		if err != nil {
			return err
		}
		acc := c.getReg(regEAX, b)
		_, nf := aluSub(acc, dst, 0, c.EFLAGS, b)
		c.EFLAGS = nf
		if acc == dst {
			return c.writeRM(m, b, c.getReg(m.reg, b))
		}
		c.setReg(regEAX, b, dst)
		return nil

	case 0xB6, 0xB7: // MOVZX
		srcBits := uint(8)
		if op2 == 0xB7 {
			srcBits = 16
		}
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		v, err := c.readRM(m, srcBits)
		if err != nil {
			return err
		}
		c.setReg(m.reg, bits, v)
		return nil

	case 0xBC, 0xBD: // BSF / BSR
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		v, err := c.readRM(m, bits)
		if err != nil {
			return err
		}
		v &= widthMask(bits)
		if v == 0 {
			c.EFLAGS |= flagZF
			return nil
		}
		c.EFLAGS &^= flagZF
		if op2 == 0xBC {
			for i := uint(0); i < bits; i++ {
				if (v>>i)&1 != 0 {
					c.setReg(m.reg, bits, uint32(i))
					break
				}
			}
		} else {
			for i := int(bits) - 1; i >= 0; i-- {
				if (v>>uint(i))&1 != 0 {
					c.setReg(m.reg, bits, uint32(i))
					break
				}
			}
		}
		return nil

	case 0xBE, 0xBF: // MOVSX
		srcBits := uint(8)
		if op2 == 0xBF {
			srcBits = 16
		}
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		v, err := c.readRM(m, srcBits)
		if err != nil {
			return err
		}
		c.setReg(m.reg, bits, uint32(signExt32(v, srcBits)))
		return nil

	case 0xC0, 0xC1: // XADD rm, r
		b := opBits(op2 == 0xC0, has66)
		m, err := c.decodeModRM(segFS)
		if err != nil {
			return err
		}
		dst, err := c.readRM(m, b)
		if err != nil {
			return err
		}
		src := c.getReg(m.reg, b)
		sum, nf := aluAdd(dst, src, 0, c.EFLAGS, b)
		c.EFLAGS = nf
		c.setReg(m.reg, b, dst)
		return c.writeRM(m, b, sum)
	}

	return fmt.Errorf("unsupported opcode 0F 0x%02x @0x%08x", op2, insnStart)
}

func (c *CPU) execXMMShift(op2, sub, xmmIdx, imm byte) {
	x := &c.XMM[xmmIdx]
	cnt := uint(imm)
	switch op2 {
	case 0x71: // 16-bit elements
		for i := 0; i < 16; i += 2 {
			v := binary.LittleEndian.Uint16(x[i:])
			var r uint16
			switch sub {
			case 2:
				if cnt < 16 {
					r = v >> cnt
				}
			case 4:
				if cnt < 16 {
					r = uint16(int16(v) >> cnt)
				} else if int16(v) < 0 {
					r = 0xFFFF
				}
			case 6:
				if cnt < 16 {
					r = v << cnt
				}
			}
			binary.LittleEndian.PutUint16(x[i:], r)
		}
	case 0x72: // 32-bit elements
		for i := 0; i < 16; i += 4 {
			v := binary.LittleEndian.Uint32(x[i:])
			var r uint32
			switch sub {
			case 2:
				if cnt < 32 {
					r = v >> cnt
				}
			case 4:
				if cnt < 32 {
					r = uint32(int32(v) >> cnt)
				} else if int32(v) < 0 {
					r = 0xFFFFFFFF
				}
			case 6:
				if cnt < 32 {
					r = v << cnt
				}
			}
			binary.LittleEndian.PutUint32(x[i:], r)
		}
	case 0x73:
		switch sub {
		case 2: // PSRLQ
			for i := 0; i < 16; i += 8 {
				v := binary.LittleEndian.Uint64(x[i:])
				if cnt < 64 {
					v >>= cnt
				} else {
					v = 0
				}
				binary.LittleEndian.PutUint64(x[i:], v)
			}
		case 6: // PSLLQ
			for i := 0; i < 16; i += 8 {
				v := binary.LittleEndian.Uint64(x[i:])
				if cnt < 64 {
					v <<= cnt
				} else {
					v = 0
				}
				binary.LittleEndian.PutUint64(x[i:], v)
			}
		case 3: // PSRLDQ (byte shift right)
			var out [16]byte
			if cnt < 16 {
				copy(out[:16-cnt], x[cnt:])
			}
			*x = out
		case 7: // PSLLDQ (byte shift left)
			var out [16]byte
			if cnt < 16 {
				copy(out[cnt:], x[:16-cnt])
			}
			*x = out
		}
	}
}
