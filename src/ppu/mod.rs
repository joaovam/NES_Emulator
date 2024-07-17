use crate::cartridge::Mirroring;

pub trait PPU {
    fn write_to_ctrl(&mut self, value: u8);
    fn write_to_mask(&mut self, value: u8);
    fn read_status(&mut self) -> u8; 
    fn write_to_oam_addr(&mut self, value: u8);
    fn write_to_oam_data(&mut self, value: u8);
    fn read_oam_data(&self) -> u8;
    fn write_to_scroll(&mut self, value: u8);
    fn write_to_ppu_addr(&mut self, value: u8);
    fn write_to_data(&mut self, value: u8);
    fn read_data(&mut self) -> u8;
    fn write_oam_dma(&mut self, value: &[u8; 256]);
}



pub struct NesPPU{
    pub chr_rom: Vec<u8>,
    pub mirroring: Mirroring,
    pub ctrl: ControlRegister,
    addr: AddrRegister,

    pub palette_table: [u8;32],
    pub vram: [u8;2048],
    pub oam_data: [u8;256],
    internal_data_buf: u8,
    
}

impl NesPPU{
    pub fn new(chr_rom: Vec<u8>, mirroring: Mirroring)-> Self{
        NesPPU{
            chr_rom,
            mirroring,
            vram: [0;2048],
            oam_data: [0; 64 * 4],
            palette_table: [0; 32],
            ctrl: ControlRegister::new(),
            addr: AddrRegister::new(),
            internal_data_buf: 0
        }
    }

    fn mirror_vram_addr(&self, addr:u16) -> u16{
        let mirrored_vram = addr & 0b10111111111111;
        let vram_index = mirrored_vram - 0x2000;
        let name_table = vram_index / 0x400;
        match (&self.mirroring, name_table) {
            (Mirroring::VERTICAL, 2) | (Mirroring::VERTICAL, 3) => vram_index - 0x800,
            (Mirroring::HORIZONTAL, 2) => vram_index - 0x400,
            (Mirroring::HORIZONTAL, 1) => vram_index - 0x400,
            (Mirroring::HORIZONTAL, 3) => vram_index - 0x800,
            _ => vram_index,    
        }
    }

    fn increment_vram_addr(&mut self){
        self.addr.increment(self.ctrl.vram_addr_increment());
    }
}

impl PPU for NesPPU{
    fn write_to_ctrl(&mut self, value: u8){
        self.ctrl.update(value);
    }

    fn write_to_ppu_addr(&mut self, value: u8){
        self.addr.update(value);
    }
    fn write_to_data(&mut self, value: u8) {
        let addr = self.addr.get();
        match addr{
            0..=0x1fff => println!("Attempt to write to chr rom space {}", addr),
            0x2000..=0x2fff =>{
                self.vram[self.mirror_vram_addr(addr) as usize] = value;
            }
            0x3000 ..=0x3eff => unimplemented!("addr {} shouldn't be used", addr),

            0x3f10 | 0x3f14 | 0x3f18 | 0x3f1c => {
                let add_mirror = addr - 0x10;
                self.palette_table[(add_mirror - 0x3f00) as usize] = value;
            }
            0x3f00..=0x3fff =>{
                self.palette_table[(addr - 0x3f00) as usize] = value;
            }
            _ => panic!("Unexpected access to mirrored space {}", addr),
        }
        self.increment_vram_addr();
    }

    fn read_data(&mut self) -> u8 {
        let addr = self.addr.get();
        self.increment_vram_addr();

        match addr{
            0..=0x1fff => {
                let result = self.internal_data_buf;
                self.internal_data_buf = self.chr_rom[addr as usize];
                result
            },
            0x2000..=0x2fff => {
                let result = self.internal_data_buf;
                self.internal_data_buf = self.vram[self.mirror_vram_addr(addr) as usize];
                result
            },
            0x3000..=0x3eff => panic!("addr space 0x3000..0x3eff is not expected to be used, requested = {} ", addr),
            0x3f00..=0x3fff =>{
                self.palette_table[(addr - 0x3f00) as usize]
            }
            _ => panic!("Unexpected access to mirrored space {}", addr)
        }
    }
}

pub struct AddrRegister{
    value: (u8,u8),
    hi_ptr: bool,
}

impl AddrRegister{
    pub fn new() -> Self{
        AddrRegister { value: (0,0),
             hi_ptr: true }
    }

    fn set(&mut self, data: u16){
        self.value.0 = (data >> 8) as u8;
        self.value.1 = (data & 0xff) as u8;
    }

    fn update(&mut self, data: u8){
        if self.hi_ptr{
            self.value.0 = data;
        }else{
            self.value.1 = data;
        }
        if self.get() > 0x3fff{
            self.set(self.get() & 0b11111111111111);
        }
        self.hi_ptr = ! self.hi_ptr;
    }

    pub fn increment(&mut self, inc: u8){
        let lo = self.value.1;
        self.value.1 = self.value.1.wrapping_add(inc);
        if lo > self.value.1{
            self.value.0 = self.value.0.wrapping_add(1);
        }
        if self.get() > 0x3fff{
            self.set(self.get() & 0b11111111111111)
        }
    }

    pub fn reset_latch(&mut self){
        self.hi_ptr = true;
    }

    pub fn get(&self) -> u16{
        ((self.value.0 as u16) << 8) | (self.value.1 as u16)
    }
}


bitflags! {

    // 7  bit  0
    // ---- ----
    // VPHB SINN
    // |||| ||||
    // |||| ||++- Base nametable address
    // |||| ||    (0 = $2000; 1 = $2400; 2 = $2800; 3 = $2C00)
    // |||| |+--- VRAM address increment per CPU read/write of PPUDATA
    // |||| |     (0: add 1, going across; 1: add 32, going down)
    // |||| +---- Sprite pattern table address for 8x8 sprites
    // ||||       (0: $0000; 1: $1000; ignored in 8x16 mode)
    // |||+------ Background pattern table address (0: $0000; 1: $1000)
    // ||+------- Sprite size (0: 8x8 pixels; 1: 8x16 pixels)
    // |+-------- PPU master/slave select
    // |          (0: read backdrop from EXT pins; 1: output color on EXT pins)
    // +--------- Generate an NMI at the start of the
    //            vertical blanking interval (0: off; 1: on)
    pub struct ControlRegister: u8 {
        const NAMETABLE1              = 0b00000001;
        const NAMETABLE2              = 0b00000010;
        const VRAM_ADD_INCREMENT      = 0b00000100;
        const SPRITE_PATTERN_ADDR     = 0b00001000;
        const BACKROUND_PATTERN_ADDR  = 0b00010000;
        const SPRITE_SIZE             = 0b00100000;
        const MASTER_SLAVE_SELECT     = 0b01000000;
        const GENERATE_NMI            = 0b10000000;
    }
 }

impl ControlRegister{
    pub fn new() -> Self{
        ControlRegister::from_bits_truncate(0b00000000)
    }
    pub fn vram_addr_increment(&self) -> u8{
        if !self.contains(ControlRegister::VRAM_ADD_INCREMENT){
            1
        }else{
            32
        }
    }
    pub fn update(&mut self, data: u8){
        self.bits = data;
    }
}
