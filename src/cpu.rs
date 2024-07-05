use std::collections::HashMap;

use crate::bus::Bus;
use crate::opcodes;

bitflags! {
    /// # Status Register (P) http://wiki.nesdev.com/w/index.php/Status_flags
    ///
    ///  7 6 5 4 3 2 1 0
    ///  N V _ B D I Z C
    ///  | |   | | | | +--- Carry Flag
    ///  | |   | | | +----- Zero Flag
    ///  | |   | | +------- Interrupt Disable
    ///  | |   | +--------- Decimal Mode (not used on NES)
    ///  | |   +----------- Break Command
    ///  | +--------------- Overflow Flag
    ///  +----------------- Negative Flag
    ///
    pub struct CpuFlags: u8 {
        const CARRY             = 0b00000001;
        const ZERO              = 0b00000010;
        const INTERRUPT_DISABLE = 0b00000100;
        const DECIMAL_MODE      = 0b00001000;
        const BREAK             = 0b00010000;
        const BREAK2            = 0b00100000;
        const OVERFLOW          = 0b01000000;
        const NEGATIVE          = 0b10000000;
    }
}

const STACK: u16 = 0x0100;
const STACK_RESET: u8 = 0xfd;

pub struct CPU {
    pub register_a: u8,
    pub register_x: u8,
    pub register_y: u8,
    pub stack_pointer: u8,
    pub status: CpuFlags,
    pub program_counter: u16,
    pub bus: Bus,
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum AddressingMode {
    Immediate,
    ZeroPage,
    ZeroPage_X,
    ZeroPage_Y,
    Absolute,
    Absolute_X,
    Absolute_Y,
    Indirect_X,
    Indirect_Y,
    NoneAddressing,
}

pub trait Mem {
    fn mem_read(&self, addr: u16) -> u8;

    fn mem_write(&mut self, addr: u16, data: u8);

    fn mem_read_u16(&self, pos: u16) -> u16 {
        let lo = self.mem_read(pos) as u16;
        let hi = self.mem_read(pos + 1) as u16;
        (hi << 8) | (lo as u16)
    }

    fn mem_write_u16(&mut self, pos: u16, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.mem_write(pos, lo);
        self.mem_write(pos + 1, hi);
    }
}

impl Mem for CPU {
    fn mem_read(&self, addr: u16) -> u8 {
        self.bus.mem_read(addr)
    }

    fn mem_write(&mut self, addr: u16, data: u8) {
        self.bus.mem_write(addr, data)
    }

    fn mem_read_u16(&self, pos: u16) -> u16 {
        self.bus.mem_read_u16(pos)
    }

    fn mem_write_u16(&mut self, pos: u16, data: u16) {
        self.bus.mem_write_u16(pos, data);
    }
}

impl CPU {
    pub fn new(bus: Bus) -> Self {
        CPU {
            register_a: 0,
            register_x: 0,
            register_y: 0,
            stack_pointer: STACK_RESET,
            status: CpuFlags::from_bits_truncate(0b100100),
            program_counter: 0,
            bus: bus,
        }
    }

    pub fn reset(&mut self) {
        self.register_a = 0;
        self.register_x = 0;
        self.register_y = 0;
        self.status = CpuFlags::from_bits_truncate(0b100100);
        self.stack_pointer = STACK_RESET;

        self.program_counter = self.mem_read_u16(0xFFFC);
    }

    pub fn load_and_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.reset();
        self.program_counter = 0x0600;
        self.run()
    }

    pub fn load(&mut self, program: Vec<u8>) {
        for i in 0..(program.len() as u16) {
            self.mem_write(0x0600 + i, program[i as usize]);
        }
    }

    pub fn run(&mut self) {
        self.run_with_callback(|_| {});
    }

    pub fn run_with_callback<F>(&mut self, mut callback: F)
    where
        F: FnMut(&mut CPU),
    {
        let ref opcodes: HashMap<u8, &'static opcodes::OpCode> = *opcodes::OPCODES_MAP;

        loop {
            callback(self);

            let code = self.mem_read(self.program_counter);

            self.program_counter += 1;
            let program_counter_state = self.program_counter;
            let opcode = opcodes
                .get(&code)
                .expect(&format!("{:x} was not recognized", code));

            //println!("Running inst {}, {:#0x}", opcode.mnemonic, code);

            match code {
                0x69 | 0x65 | 0x75 | 0x6D | 0x7D | 0x79 | 0x61 | 0x71 => self.adc(&opcode.mode),

                0x29 | 0x25 | 0x35 | 0x2D | 0x3D | 0x39 | 0x21 | 0x31 => self.and(&opcode.mode),

                0x0a => self.asl_acc(),

                0x06 | 0x16 | 0x0E | 0x1E => {
                    self.asl(&opcode.mode);
                }

                0x90 => self.branch(!self.status.contains(CpuFlags::CARRY)),
                0xB0 => self.branch(self.status.contains(CpuFlags::CARRY)),
                0xF0 => self.branch(self.status.contains(CpuFlags::ZERO)),

                0x24 | 0x2c => self.bit(&opcode.mode),

                0x30 => self.branch(self.status.contains(CpuFlags::NEGATIVE)),
                0x10 => self.branch(!self.status.contains(CpuFlags::NEGATIVE)),
                0xD0 => self.branch(!self.status.contains(CpuFlags::ZERO)),
                0x50 => self.branch(!self.status.contains(CpuFlags::OVERFLOW)),
                0x70 => self.branch(self.status.contains(CpuFlags::OVERFLOW)),
                0x18 => self.status.remove(CpuFlags::CARRY),
                0xD8 => self.status.remove(CpuFlags::DECIMAL_MODE),
                0x58 => self.status.remove(CpuFlags::INTERRUPT_DISABLE),
                0xB8 => self.status.remove(CpuFlags::OVERFLOW),
                0xC9 | 0xC5 | 0xD5 | 0xCD | 0xDD | 0xD9 | 0xC1 | 0xD1 => {
                    self.compare(&opcode.mode, self.register_a)
                }

                0xE0 | 0xE4 | 0xEC => self.compare(&opcode.mode, self.register_x),

                0xC0 | 0xC4 | 0xCC => self.compare(&opcode.mode, self.register_y),

                0xC6 | 0xD6 | 0xCE | 0xDE => self.dec(&opcode.mode),

                0xCA => self.dex(),
                0x88 => self.dey(),

                0x49 | 0x45 | 0x55 | 0x4d | 0x5d | 0x59 | 0x41 | 0x51 => self.eor(&opcode.mode),

                0xe6 | 0xf6 | 0xee | 0xfe => self.inc(&opcode.mode),

                0xe8 => self.inx(),

                0xc8 => self.iny(),

                //jmp absolute
                0x4c => {
                    let addr = self.mem_read_u16(self.program_counter);
                    self.program_counter = addr;
                }
                //jmp indirect
                0x6c => {
                    let addr = self.mem_read_u16(self.program_counter);

                    let ind_ref = if addr & 0x00FF == 0x00FF {
                        let lo = self.mem_read(addr);
                        let hi = self.mem_read(addr & 0xFF00);
                        (hi as u16) << 8 | (lo as u16)
                    } else {
                        self.mem_read_u16(addr)
                    };
                    self.program_counter = ind_ref;
                }
                //jsr
                0x20 => {
                    self.stack_push_u16(self.program_counter + 2 - 1);
                    let mem_addr = self.mem_read_u16(self.program_counter);
                    self.program_counter = mem_addr
                }

                0xa9 | 0xa5 | 0xb5 | 0xad | 0xbd | 0xb9 | 0xa1 | 0xb1 => {
                    self.lda(&opcode.mode);
                }
                0xa2 | 0xa6 | 0xb6 | 0xae | 0xbe => self.ldx(&opcode.mode),

                0xa0 | 0xa4 | 0xb4 | 0xac | 0xbc => self.ldy(&opcode.mode),

                //lsr accumulator
                0x4a => {
                    let data = self.register_a;
                    if data & 1 == 1 {
                        self.sec();
                    } else {
                        self.clc();
                    }
                    self.register_a = data >> 1;
                    self.update_zeros_and_negative_flags(self.register_a);
                }

                0x46 | 0x56 | 0x4e | 0x5e => self.lsr(&opcode.mode),

                //NOP
                0xea => {}
                0x09 | 0x05 | 0x15 | 0x0d | 0x1d | 0x19 | 0x01 | 0x11 => self.ora(&opcode.mode),

                0x48 => self.pha(),

                0x08 => self.php(),

                0x68 => self.pla(),
                0x28 => self.plp(),

                0x2a => self.rol_accumulator(),

                0x26 | 0x36 | 0x2e | 0x3e => self.rol(&opcode.mode),

                0x6a => self.ror_accumulator(),

                0x66 | 0x76 | 0x6e | 0x7e => self.ror(&opcode.mode),

                0x40 => self.rti(),

                0x60 => self.rts(),

                0xe9 | 0xe5 | 0xf5 | 0xed | 0xfd | 0xf9 | 0xe1 | 0xf1 => self.sbc(&opcode.mode),

                0x38 => self.sec(),
                0xF8 => self.sed(),
                0x78 => self.sei(),

                //STA
                0x85 | 0x95 | 0x8d | 0x9d | 0x99 | 0x81 | 0x91 => {
                    self.sta(&opcode.mode);
                }
                0x86 | 0x96 | 0x8E => self.stx(&opcode.mode),

                0x84 | 0x94 | 0x8c => self.sty(&opcode.mode),

                0xAA => self.tax(),
                0xA8 => self.tay(),
                0xBA => self.tsx(),
                0x8A => self.txa(),
                0x9A => self.txs(),
                0x98 => self.tya(),

                0x00 => return,

                //unofficial

                //DCP
                0xc7 | 0xd7 | 0xcf | 0xdf | 0xdb | 0xd3 | 0xc3 =>{
                    let addr = self.get_operand_addresses(&opcode.mode);
                    let mut val = self.mem_read(addr);

                    val = val.wrapping_sub(1);

                    if val <= self.register_a{
                        self.status.insert(CpuFlags::CARRY);
                    }

                    self.update_zeros_and_negative_flags(self.register_a.wrapping_sub(val));
                },

                //RLA
                0x27 | 0x37 | 0x2f | 0x3f | 0x3b | 0x33 | 0x23 =>{
                    let data = self.rol(&opcode.mode);
                    self.register_a = self.register_a & data;
                    self.update_zeros_and_negative_flags(self.register_a);
                },

                //SLO
                0x07 | 0x17 | 0x0f | 0x1f | 0x1b | 0x03 | 0x13 =>{
                    let data = self.asl(&opcode.mode);
                    self.register_a = self.register_a | data;
                    self.update_zeros_and_negative_flags(self.register_a);
                }

                //SRE
                0x47 | 0x57 | 0x4f | 0x5f | 0x5b | 0x43 | 0x53 =>{
                    let data = self.lsr(&opcode.mode);
                    self.register_a = data ^ self.register_a;
                    self.update_zeros_and_negative_flags(self.register_a);
                },

                //SKB
                0x80 | 0x82 | 0x89 | 0xc2 | 0xe2 => {
                    /* 2 byte NOP (immediate ) */
                    // todo: might be worth doing the read
                },

                //AXS
                0xcb =>{
                    let addr = self.get_operand_addresses(&opcode.mode);
                    let data = self.mem_read(addr);
                    let and = self.register_x & self.register_a;
                    let r = and.wrapping_sub(data);
                    if data <= and{
                        self.status.insert(CpuFlags::CARRY);
                    }

                    self.update_zeros_and_negative_flags(r);
                    self.register_x = r;
                }

                //ARR
                0x6b =>{
                    let addr = self.get_operand_addresses(&opcode.mode);
                    let val = self.mem_read(addr);
                    self.register_a = self.register_a & data;
                    self.ror_accumulator();

                    let r = self.register_a;
                    let b5 = (r>>5) & 1;
                    let b6 = (r>>6) & 1;

                    if b6 == 1{
                        self.status.insert(CpuFlags::CARRY);
                    }else{
                        self.status.remove(CpuFlags::CARRY);
                    }

                    if b5 ^ b6{
                        self.status.in
                    }
                }



                _ => todo!(),
            }
            if program_counter_state == self.program_counter {
                self.program_counter += (opcode.len - 1) as u16;
            }
        }
    }

    fn adc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);
        let val = self.mem_read(addr);

        self.add_to_register_a(val);
    }

    fn add_to_register_a(&mut self, val: u8) {
        let sum = self.register_a as u16
            + val as u16
            + (if self.status.contains(CpuFlags::CARRY) {
                1
            } else {
                0
            }) as u16;
        if sum > 0xff {
            self.status.insert(CpuFlags::CARRY)
        } else {
            self.status.remove(CpuFlags::CARRY);
        }
        let result = sum as u8;

        if (val ^ result) & (result ^ self.register_a) & 0x80 != 0 {
            self.status.insert(CpuFlags::OVERFLOW);
        } else {
            self.status.remove(CpuFlags::OVERFLOW)
        }

        self.register_a = result;
        self.update_zeros_and_negative_flags(result);
    }

    fn and(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);
        let value = self.mem_read(addr);
        eprintln!("value: {:02x} & A: {:02x} = {:02x}",value, self.register_a, value & self.register_a);

        self.register_a = value & self.register_a;
        self.update_zeros_and_negative_flags(self.register_a);
    }

    fn asl_acc(&mut self) {
        let mut val = self.register_a;

        if val >> 7 == 1 {
            self.sec();
        } else {
            self.clc();
        }
        val = val << 1;
        self.register_a = val;
        self.update_zeros_and_negative_flags(self.register_a);
    }

    fn asl(&mut self, mode: &AddressingMode) -> u8 {
        let addr = self.get_operand_addresses(mode);
        let mut val = self.mem_read(addr);
        if val >> 7 == 1 {
            self.sec();
        } else {
            self.clc();
        }
        val = val << 1;
        self.mem_write(addr, val);
        self.update_zeros_and_negative_flags(val);
        val
    }

    fn bit(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);

        let v = self.mem_read(addr);

        let and = v & self.register_a;

        if and == 0 {
            self.status.insert(CpuFlags::ZERO)
        } else {
            self.status.remove(CpuFlags::ZERO)
        }

        self.status.set(CpuFlags::NEGATIVE, v & 0b10000000  > 0);
        self.status.set(CpuFlags::OVERFLOW, v & 0b01000000 > 0)
    }

    fn clc(&mut self) {
        self.status.remove(CpuFlags::CARRY);
    }

    fn compare(&mut self, mode: &AddressingMode, compare_with: u8) {
        let addr = self.get_operand_addresses(mode);
        let val = self.mem_read(addr);

        if val <= compare_with {
            self.status.insert(CpuFlags::CARRY);
        }else{
            self.status.remove(CpuFlags::CARRY);
        }
        self.update_zeros_and_negative_flags(compare_with.wrapping_sub(val));
    }
    fn dec(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);
        let mut val = self.mem_read(addr);

        val = val.wrapping_sub(1);
        self.update_zeros_and_negative_flags(val);
        self.mem_write(addr, val);
    }

    fn dex(&mut self) {
        self.register_x = self.register_x.wrapping_sub(1);
        self.update_zeros_and_negative_flags(self.register_x);
    }

    fn dey(&mut self) {
        self.register_y = self.register_y.wrapping_sub(1);
        self.update_zeros_and_negative_flags(self.register_y);
    }

    fn eor(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);
        let val = self.mem_read(addr);
        self.register_a ^= val;
        self.update_zeros_and_negative_flags(self.register_a);
    }

    fn inc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);
        let mut val = self.mem_read(addr);
        val = val.wrapping_add(1);
        self.update_zeros_and_negative_flags(val);
        self.mem_write(addr, val);
    }

    fn inx(&mut self) {
        self.register_x = self.register_x.wrapping_add(1);

        self.update_zeros_and_negative_flags(self.register_x);
    }

    fn iny(&mut self) {
        self.register_y = self.register_y.wrapping_add(1);
        self.update_zeros_and_negative_flags(self.register_y);
    }
    fn lsr(&mut self, mode: &AddressingMode) -> u8 {
        let addr = self.get_operand_addresses(mode);
        let mut data = self.mem_read(addr);
        if data & 1 == 1 {
            self.sec();
        } else {
            self.clc();
        }

        data = data >> 1;
        self.mem_write(addr, data);
        self.update_zeros_and_negative_flags(data);
        data
    }

    fn ora(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);
        let val = self.mem_read(addr);

        self.register_a |= val;
        self.update_zeros_and_negative_flags(self.register_a);
    }

    fn pha(&mut self) {
        self.stack_push(self.register_a);
    }
    fn php(&mut self) {
        let mut f = self.status.clone();
        f.insert(CpuFlags::BREAK);
        f.insert(CpuFlags::BREAK2);
        self.stack_push(f.bits());
    }
    fn pla(&mut self) {
        self.register_a = self.stack_pop();
        self.update_zeros_and_negative_flags(self.register_a);
    }

    fn plp(&mut self) {
        self.status = CpuFlags::from_bits_truncate(self.stack_pop());
        self.status.remove(CpuFlags::BREAK);
        self.status.insert(CpuFlags::BREAK2);
    }

    fn rol_accumulator(&mut self) {
        let old_carry = self.status.contains(CpuFlags::CARRY);
        let mut data = self.register_a;

        if data >> 7 == 1 {
            self.sec();
        } else {
            self.clc();
        }
        data <<= 1;

        if old_carry {
            data |= 1;
        }

        self.register_a = data;
        self.update_zeros_and_negative_flags(data);
    }

    fn rol(&mut self, mode: &AddressingMode) {
        let old_carry = self.status.contains(CpuFlags::CARRY);
        let addr = self.get_operand_addresses(mode);
        let mut data = self.mem_read(addr);

        if data >> 7 == 1 {
            self.sec();
        } else {
            self.clc();
        }
        data <<= 1;

        if old_carry {
            data |= 1;
        }

        self.mem_write(addr, data);
        self.update_negative_flags(data);
    }

    fn ror_accumulator(&mut self) {

        let old_carry = self.status.contains(CpuFlags::CARRY);
        let mut data = self.register_a;

        if data & 1 == 1 {
            self.sec();
        } else {
            self.clc();
        }
        data >>= 1;

        if old_carry {
            data |= 0b10000000;
        }

        self.register_a = data;
        self.update_zeros_and_negative_flags(data);
    }

    fn ror(&mut self, mode: &AddressingMode) {
        let old_carry = self.status.contains(CpuFlags::CARRY);
        let addr = self.get_operand_addresses(mode);
        let mut data = self.mem_read(addr);

        if data & 1 == 1 {
            self.sec();
        } else {
            self.clc();
        }
        data >>= 1;

        if old_carry {
            data |= 0b10000000;
        }

        self.mem_write(addr, data);
        self.update_negative_flags(data);
    }

    fn rti(&mut self) {
        self.status.bits = self.stack_pop();
        self.status.remove(CpuFlags::BREAK);
        self.status.insert(CpuFlags::BREAK2);
        self.program_counter = self.stack_pop_u16();
    }

    fn rts(&mut self) {
        self.program_counter = self.stack_pop_u16() + 1;
    }

    fn sbc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);
        let val = self.mem_read(addr);

        self.add_to_register_a((val as i8).wrapping_neg().wrapping_sub(1) as u8);
    }

    fn sec(&mut self) {
        self.status.insert(CpuFlags::CARRY);
    }
    fn sed(&mut self) {
        self.status.insert(CpuFlags::DECIMAL_MODE);
    }

    fn sei(&mut self) {
        self.status.insert(CpuFlags::INTERRUPT_DISABLE);
    }

    fn sta(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);
        self.mem_write(addr, self.register_a);
    }

    fn stx(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);
        self.mem_write(addr, self.register_x);
    }

    fn sty(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);
        self.mem_write(addr, self.register_y);
    }
    fn tax(&mut self) {
        self.register_x = self.register_a;
        self.update_zeros_and_negative_flags(self.register_x);
    }
    fn tay(&mut self) {
        self.register_y = self.register_a;
        self.update_zeros_and_negative_flags(self.register_y);
    }

    fn txa(&mut self) {
        self.register_a = self.register_x;
        self.update_zeros_and_negative_flags(self.register_a);
    }

    fn tsx(&mut self) {
        self.register_x = self.stack_pointer;
        self.update_zeros_and_negative_flags(self.register_x);
    }

    fn txs(&mut self) {
        self.stack_pointer = self.register_x;
    }

    fn tya(&mut self) {
        self.register_a = self.register_y;
        self.update_zeros_and_negative_flags(self.register_a);
    }

    fn branch(&mut self, condition: bool) {
        if condition {
            let jump = self.mem_read(self.program_counter) as i8;

            let jump_addr = self
                .program_counter
                .wrapping_add(1)
                .wrapping_add(jump as u16);
            self.program_counter = jump_addr;
        }
    }
    fn lda(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(&mode);
        let value = self.mem_read(addr);
        self.register_a = value;
        self.update_zeros_and_negative_flags(self.register_a);
    }

    fn ldx(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);
        let value = self.mem_read(addr);
        self.register_x = value;
        self.update_zeros_and_negative_flags(self.register_x);
    }

    fn ldy(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);
        let value = self.mem_read(addr);
        self.register_y = value;
        self.update_zeros_and_negative_flags(self.register_y);
    }

    fn update_zeros_and_negative_flags(&mut self, result: u8) {
        if result == 0 {
            self.status.insert(CpuFlags::ZERO);
        } else {
            self.status.remove(CpuFlags::ZERO);
        }

        if result >> 7 == 1 {
            self.status.insert(CpuFlags::NEGATIVE);
        } else {
            self.status.remove(CpuFlags::NEGATIVE);
        }
    }

    fn update_negative_flags(&mut self, result: u8) {
        if result >> 7 == 1 {
            self.status.insert(CpuFlags::NEGATIVE)
        } else {
            self.status.remove(CpuFlags::NEGATIVE)
        }
    }

    fn stack_push(&mut self, data: u8) {
        self.mem_write((STACK as u16) + self.stack_pointer as u16, data);
        self.stack_pointer = self.stack_pointer.wrapping_sub(1)
    }

    fn stack_pop(&mut self) -> u8 {
        self.stack_pointer = self.stack_pointer.wrapping_add(1);
        
        let x = self.mem_read((STACK as u16) + self.stack_pointer as u16);
        eprintln!("Reading: {:02x}", x);
        x
    }

    fn stack_push_u16(&mut self, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xFF) as u8;

        self.stack_push(hi);
        self.stack_push(lo);
    }
    fn stack_pop_u16(&mut self) -> u16 {
        let lo = self.stack_pop() as u16;
        let hi = self.stack_pop() as u16;
        hi << 8 | lo
    }

    pub fn get_absolute_address(&self, mode: &AddressingMode, addr: u16) -> u16 {
        match mode {
            AddressingMode::ZeroPage => self.mem_read(addr) as u16,

            AddressingMode::Absolute => self.mem_read_u16(addr),

            AddressingMode::ZeroPage_X => {
                let pos = self.mem_read(addr);
                let addr = pos.wrapping_add(self.register_x) as u16;
                addr
            }
            AddressingMode::ZeroPage_Y => {
                let pos = self.mem_read(addr);
                let addr = pos.wrapping_add(self.register_y) as u16;
                addr
            }

            AddressingMode::Absolute_X => {
                let base = self.mem_read_u16(addr);
                let addr = base.wrapping_add(self.register_x as u16);
                addr
            }
            AddressingMode::Absolute_Y => {
                let base = self.mem_read_u16(addr);
                let addr = base.wrapping_add(self.register_y as u16);
                addr
            }

            AddressingMode::Indirect_X => {
                let base = self.mem_read(addr);

                let ptr: u8 = (base as u8).wrapping_add(self.register_x);
                let lo = self.mem_read(ptr as u16);
                let hi = self.mem_read(ptr.wrapping_add(1) as u16);
                (hi as u16) << 8 | (lo as u16)
            }
            AddressingMode::Indirect_Y => {
                let base = self.mem_read(addr);

                let lo = self.mem_read(base as u16);
                let hi = self.mem_read((base as u8).wrapping_add(1) as u16);
                let deref_base = (hi as u16) << 8 | (lo as u16);
                let deref = deref_base.wrapping_add(self.register_y as u16);
                deref
            }

            _ => {
                panic!("mode {:?} is not supported", mode);
            }
        }
    }

    fn get_operand_addresses(&self, mode: &AddressingMode) -> u16 {
        match mode {
            AddressingMode::Immediate => self.program_counter,
            _ => self.get_absolute_address(mode, self.program_counter),
        }
    }
}

#[cfg(test)]
#[cfg(test)]
mod test {
    use super::*;
    use crate::cartridge::test;

    #[test]
    fn test_0xa9_lda_immediate_load_data() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.load_and_run(vec![0xa9, 0x05, 0x00]);
        assert_eq!(cpu.register_a, 5);
        assert!(cpu.status.bits() & 0b0000_0010 == 0b00);
        assert!(cpu.status.bits() & 0b1000_0000 == 0);
    }

    #[test]
    fn test_5_ops_working_together() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.load_and_run(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 0xc1)
    }

    #[test]
    fn test_lda_from_memory() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.mem_write(0x10, 0x55);

        cpu.load_and_run(vec![0xa5, 0x10, 0x00]);

        assert_eq!(cpu.register_a, 0x55);
    }
}
