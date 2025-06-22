# 总结与反思
过去四周虽然付出了很多努力，但效率不高，我总结出以下几点原因：

1. 一开始我想节约时间，只想关注当前所需内容，不愿深究每个细节。结果往往是：初步判断某个细节不重要就跳过，既不深挖也不记录整理。等到后续工作涉及到相关知识时，才发现它其实很关键，而我又记不清了，不得不回头重学，反而浪费了大量时间。后来我意识到，恰恰是那些我认为“不重要”的细节，构成了我的知识框架。

2. 看了大量资料，但整理过于随意，回顾困难。不过，如果第一点提到的知识框架没建立好，确实很难实现有效整理（这点还需继续体会）。最后两天集中整理时，我把知识点串联起来，思路才变得清晰。所以我觉得在确保自己理解了理论和代码后，就应该立即以费曼的方式写下来（单纯复制粘贴无效）。当时主要是担心时间不够，但现在反思来看，知识点未能串联导致反复遗忘，才是最大的时间浪费。

3. 过度依赖AI代码： 项目中使用的AI生成代码常常不遵循手册规范，而我自己对细节理解也不够深入。在调试过程中，反复尝试耗费了大量时间。前三点都指向了我的学习方式存在问题。

4. 开发流程经验不足： 没有充分利用 cargo check 来保证代码基础编译通过。我起初的想法是先写完再调试，结果调试时发现早期代码就有问题，不得不回溯修改，效率就低了。另一个问题是，rust-analyzer 有时无法识别某些库的语法，让我无法确定代码是否正确。这种情况下，频繁使用 cargo check 就非常必要了。

5. 代码理解方式不当：应该按执行流程逐行阅读。我之前按文件结构/模块逐行阅读，ai问了一堆，但是串不起来，等于啥也没学到。现有的文档基本也是按文件结构/模块，我认为这并不是初学者友好的。我一开始读axvisor，遇到一个 trait 定义在一个位置，其实现在另一处，由于对这种写法不熟悉，这种写法不熟悉，ide功能又有限，我就不知道在哪找实际实现。但是如果从最开始的一行行捋，而不是单看那一块，就能捋明白。

6. 问题记录与分析缺失，这一点算是对第1点的补充，因为怕来不及，所以很多问题没有被我写下来，就是问了ai，觉得不重要就过了。我觉得如果我判断出这部分不重要，那我就应该写下来，逻辑清晰的写出，这部分为什么不重要，这样理解加深了，也方便后续检索。并且有了ai之后，我都有点懒了，就是不愿意自己分析问题了，直接ai分析，最后也是不出意外的调试很久都不行，还得自己重新思考。

7. 总想着一开始就和vmx中的注释统一，还要全英的，搞错了重点，应该先跑起来的。

后续开发计划：注重理解和写作，过程中可以写一部分小的代码辅助理解，最重要的是理解，核心在于理解而非产出代码。过去经验说明，追求速度、堆砌代码，往往导致后续反复调试，最终仍需回头补足理解，这不仅是巨大的时间浪费，更剥夺了学习的反馈感，就好像把人沦为了ai的调试工具。

# 文档类

类似于开发日志，就把我开发过程中的一些思考点都写进去了，但是不是很完善，：https://www.zhixi.com/view/3f551879

写PPT时候的思路：链接：https://www.zhixi.com/view/ff926e7c

下面这些笔记就能体现我反思所提到的内容，比如我一开始就没有按流程逐行理解，后面按流程逐行了。所以笔记写的并不是很好：

RVM1.5笔记：https://www.zhixi.com/view/ebc6c1c8

RVM-tutorial笔记，按流程逐行解析：https://www.zhixi.com/view/9140beea

axvisor笔记按流程逐行解析，这里的最后部分和付权智同学交流了，觉得搞懂了就没有写进去了https://www.zhixi.com/view/99a939ce

**用到的资料：**

RVM-tutorial，vmx的教学：https://github.com/equation314/RVM-Tutorial
RVM1.5，svm的参考代码：https://github.com/rcore-os/RVM1.5

## axvisor流程

以内存启动为例

0.检查是否支持

1.给smp个cpu core开启虚拟化

2.创建vm，具体来说就是绑定vcpu和cpu core，设置地址空间、设备，设置vcpu的entry，把vm装入vmlist

3.加载bios和os到内存位置

4.给主vcpu分配task，把task绑定到vcpu对应的cpu core上。

5.task加入到vm_cpus中，并加入到全局的 虚拟机vcpu管理器，意味着不同的vm，可以通过这个来调度。

也完成了 通过调度vcpu任务进而调度cpu core，并且任务只安排在一个cpu core执行。

不会出现vcpu任务在不同的cpu core执行。

6.vmm start，也就是通知主vcpu启动

7.等待所有vm执行完毕退出

补充：
①一个vm的其他vcpu由主vcpu启动，vcpu设置什么的在config
②alloc task的时候会把task绑定cpu core

# 工作进度
只完成了进入guest之前的配置，包括检查虚拟化支持、启用虚拟化、完善结构、配置结构，但是可能配置的不对，vmrun之后死循环了还没调出来。具体的代码主要是在mycrate/x86_vcpu/src/svm中，github链接：https://github.com/1906353110/axvisor/tree/iopm_msrpm

讲解在ppt。https://github.com/1906353110/oscamp_report/blob/main/oscamp_final_ppt.pptx

因为我的工作不只是代码，还包括写x86_vcpu的文档，所以ppt里面呈现的内容其实也算我的工作，因为不仅包括了svm的代码，还包括和vmx对比。

从功能上来说，代码基本都实现了，但是不够完善，同时vmrun没有跑起来，所以很多功能写出来了但是没有测试。花的时间最久的是vmcb、iopm、msrpm，这地方是看文档看的最多的，ai写的完全不符合规范。

主要代码就放最后了。

# 感想
这两个月真的学到了很多很多，很多思路都是我以前没尝试过的，比如根据rip看汇编、看qemu日志、makefile、看全英文档、逐行读代码（之前源码阅读经验基本为0）等等，也是走出舒适区吧，几乎每几天都有卡住我的问题，然后我就不得不逼自己重新思考，重新学习。当时真觉得还挺痛苦的哈哈哈哈哈，觉得自己做不成了，但每次又能够找到解决问题的方向，现在回过头来看，真的学到很多。

汇报的时候，我发现别人主要是简单介绍原因，然后说做了什么工作，实现的逻辑不重要，感觉我说了太多为什么这么做，汇报的效果不是很好。

后续就把vmx和svm的对比以及为axvisor支持svm当作我的毕设吧！

# 主要代码

## VMCB

```rust
register_structs![
    pub VmcbControlArea {
        (0x0000 => pub intercept_cr:         ReadWrite<u32, InterceptCrRw::Register>),
        (0x0004 => pub intercept_dr:         ReadWrite<u32, InterceptDrRw::Register>),

        (0x0008 => pub intercept_exceptions: ReadWrite<u32, InterceptExceptions::Register>),
        (0x000C => pub intercept_vector3:    ReadWrite<u32, InterceptVec3::Register>),
        (0x0010 => pub intercept_vector4:    ReadWrite<u32, InterceptVec4::Register>),
        (0x0014 => pub intercept_vector5:    ReadWrite<u32, InterceptVec5::Register>),
        (0x0018 => _reserved_0018),
        (0x003C => pub pause_filter_thresh:   ReadWrite<u16>),
        (0x003E => pub pause_filter_count:    ReadWrite<u16>),
    }]

/// Virtual-Machine Control Block (VMCB)
/// One 4 KiB page per vCPU: [control-area | save-area].
#[derive(Debug)]
pub struct VmcbFrame<H: AxVCpuHal> {
    page: PhysFrame<H>,
}

impl<H: AxVCpuHal> VmcbFrame<H> {
    pub const unsafe fn uninit() -> Self {
        Self { page: unsafe { PhysFrame::uninit() } }
    }

    pub fn new() -> AxResult<Self> {
        Ok(Self { page: PhysFrame::alloc_zero()? })
    }

    pub fn phys_addr(&self) -> HostPhysAddr {
        self.page.start_paddr()
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.page.as_mut_ptr()
    }
}

/// Unified façade returning typed accessors to both halves of the VMCB.
pub struct Vmcb<'a> {
    pub control: &'a mut VmcbControlArea,
    pub state:   &'a mut VmcbStateSaveArea,
}

impl<H: AxVCpuHal> VmcbFrame<H> {
    /// # Safety
    /// caller must guarantee the page is mapped
    pub unsafe fn as_vmcb<'a>(&'a self) -> Vmcb<'a> {
        let base = self.as_mut_ptr();

        Vmcb {
            control: &mut *(base as *mut VmcbControlArea),
            state:   &mut *(base.add(0x400) as *mut VmcbStateSaveArea),
        }
    }
}

impl Vmcb <'_>{
    /// Zero‑initialise the control area
    pub fn clear_control(&mut self) {
        unsafe { core::ptr::write_bytes(self.control as *mut _ as *mut u8, 0, 0x400) };
    }
    pub fn clean_bits(&mut self)-> &mut ReadWrite<u32, VmcbCleanBits::Register> {
        &mut self.control.clean_bits
    }
}

pub fn set_vmcb_segment(seg: &mut VmcbSegment, selector: u16, attr: u16) {
    seg.selector.set(selector); // 一般初始化阶段都传 0
    seg.base.set(0);            // 实模式／平坦段：基址 0
    seg.limit.set(0xFFFF);      // 64 KiB 段界限
    seg.attr.set(attr);         // AR 字节（0x93, 0x9B, 0x8B, 0x82 …）
}

```

## 申请连续页帧

```rust
impl AxVCpuHal for AxVCpuHalImpl {
fn alloc_contiguous_frames(count: usize) -> Option<HostPhysAddr> {
           axalloc::global_allocator()
                .alloc_pages(count, PAGE_SIZE_4K)
                .map(|vaddr| virt_to_phys(vaddr.into()))
                .ok()
    }

    fn dealloc_contiguous_frames(paddr: HostPhysAddr, count: usize) {
        axalloc::global_allocator().dealloc_pages(phys_to_virt(paddr).as_usize(), count)
    }
}


/// A contiguous block of physical memory frames that will be automatically
/// deallocated when dropped. Used for hardware structures requiring contiguous
/// physical memory (e.g., IOPM, MSRPM).
#[derive(Debug)]
pub struct ContiguousPhysFrames<H: AxVCpuHal> {
    start_paddr: Option<HostPhysAddr>,
    frame_count: usize,
    _marker: PhantomData<H>,
}

impl<H: AxVCpuHal> ContiguousPhysFrames<H> {
    pub fn alloc(frame_count: usize) -> AxResult<Self> {
        let start_paddr = H::alloc_contiguous_frames(frame_count)
            .ok_or_else(|| ax_err_type!(NoMemory, "allocate contiguous frames failed"))?;

        assert_ne!(start_paddr.as_usize(), 0);
        Ok(Self {
            start_paddr: Some(start_paddr),
            frame_count,
            _marker: PhantomData,
        })
    }

    pub fn alloc_zero(frame_count: usize) -> AxResult<Self> {
        let mut frames = Self::alloc(frame_count)?;
        frames.fill(0);
        Ok(frames)
    }

    pub const unsafe fn uninit() -> Self {
        Self {
            start_paddr: None,
            frame_count: 0,
            _marker: PhantomData,
        }
    }


    pub fn start_paddr(&self) -> HostPhysAddr {
        self.start_paddr.expect("uninitialized ContiguousPhysFrames")
    }

    pub fn frame_count(&self) -> usize {
        self.frame_count
    }

    pub fn size(&self) -> usize {
        PAGE_SIZE * self.frame_count
    }


    pub fn as_mut_ptr(&self) -> *mut u8 {
        H::phys_to_virt(self.start_paddr()).as_mut_ptr()
    }


    pub fn fill(&mut self, byte: u8) {
        unsafe {
            core::ptr::write_bytes(self.as_mut_ptr(), byte, self.size());
        }
    }
}

impl<H: AxVCpuHal> Drop for ContiguousPhysFrames<H> {
    fn drop(&mut self) {
        if let Some(start_paddr) = self.start_paddr {
            H::dealloc_contiguous_frames(start_paddr, self.frame_count);
            debug!(
                "[AxVM] deallocated ContiguousPhysFrames({:#x}, {} frames)",
                start_paddr, self.frame_count
            );
        }
    }
}
```

## IOPm和MSRPm
```rust
// (AMD64 APM Vol.2, Section 15.10)
// The I/O Permissions Map (IOPM) occupies 12 Kbytes of contiguous physical memory.
// The map is structured as a linear array of 64K+3 bits (two 4-Kbyte pages, and the first three bits of a third 4-Kbyte page) and must be aligned on a 4-Kbyte boundary;
#[derive(Debug)]
pub struct IOPm<H: AxVCpuHal> {
    frames: ContiguousPhysFrames<H>,  // 3 contiguous frames (12KB)
}

impl<H: AxVCpuHal> IOPm<H> {
    pub fn passthrough_all() -> AxResult<Self> {
        let mut frames = ContiguousPhysFrames::<H>::alloc_zero(3)?;

        // Set first 3 bits of third frame to intercept (ports > 0xFFFF)
        let third_frame_start = frames.as_mut_ptr() as usize + 2 * PAGE_SIZE;
        unsafe {
            let third_byte = third_frame_start as *mut u8;
            *third_byte |= 0x07; // Set bits 0-2 (0b00000111)
        }

        Ok(Self { frames })
    }

    #[allow(unused)]
    pub fn intercept_all() -> AxResult<Self> {
        let mut frames = ContiguousPhysFrames::<H>::alloc(3)?;
        frames.fill(0xFF); // Set all bits to 1 (intercept)
        Ok(Self { frames })
    }

    pub fn phys_addr(&self) -> HostPhysAddr {
        self.frames.start_paddr()
    }
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.frames.as_mut_ptr()
    }

    pub fn set_intercept(&mut self, port: u32, intercept: bool) {
        let byte_index = port as usize / 8;
        let bit_offset = (port % 8) as u8;
        let iopm_ptr = self.frames.as_mut_ptr();

        unsafe {
            let byte_ptr = iopm_ptr.add(byte_index);
            if intercept {
                *byte_ptr |= 1 << bit_offset;
            } else {
                *byte_ptr &= !(1 << bit_offset);
            }
        }
    }

    pub fn set_intercept_of_range(&mut self, port_base: u32, count: u32, intercept: bool) {
        for port in port_base..port_base + count {
            self.set_intercept(port, intercept)
        }
    }

}
// (AMD64 APM Vol.2, Section 15.10)
// The VMM can intercept RDMSR and WRMSR instructions by means of the SVM MSR permissions map (MSRPM) on a per-MSR basis
// The four separate bit vectors must be packed together and located in two contiguous physical pages of memory.
#[derive(Debug)]
pub struct MSRPm<H: AxVCpuHal> {
    frames: ContiguousPhysFrames<H>,
}

impl<H: AxVCpuHal> MSRPm<H> {
    pub fn passthrough_all() -> AxResult<Self> {
        Ok(Self {
            frames: ContiguousPhysFrames::alloc_zero(2)?,
        })
    }

    #[allow(unused)]
    pub fn intercept_all() -> AxResult<Self> {
        let mut frames = ContiguousPhysFrames::alloc(2)?;
        frames.fill(0xFF);
        Ok(Self { frames })
    }

    pub fn phys_addr(&self) -> HostPhysAddr {
        self.frames.start_paddr()
    }
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.frames.as_mut_ptr()
    }

    pub fn set_intercept(&mut self, msr: u32, is_write: bool, intercept: bool) {
        let (segment, msr_low) = if msr <= 0x1fff {
            (0u32, msr)
        } else if (0xc000_0000..=0xc000_1fff).contains(&msr) {
            (1u32, msr & 0x1fff)
        } else if (0xc001_0000..=0xc001_1fff).contains(&msr) {
            (2u32, msr & 0x1fff)
        } else {
            unreachable!("MSR {:#x} Not supported by MSRPM", msr);
        };

        let base_offset      = (segment * 2048) as usize;

        let byte_in_segment  = (msr_low as usize) / 4;
        let bit_pair_offset  = ((msr_low & 0b11) * 2) as u8;      // 0,2,4,6
        let bit_offset       = bit_pair_offset + is_write as u8;  // +0=读, +1=写

        unsafe {
            let byte_ptr = self
                .frames
                .as_mut_ptr()
                .add(base_offset + byte_in_segment);

            let old = core::ptr::read_volatile(byte_ptr);
            let new = if intercept {
                old | (1u8 << bit_offset)
            } else {
                old & !(1u8 << bit_offset)
            };
            core::ptr::write_volatile(byte_ptr, new);
        }
    }

    pub fn set_read_intercept(&mut self, msr: u32, intercept: bool) {
        self.set_intercept(msr, false, intercept);
    }

    pub fn set_write_intercept(&mut self, msr: u32, intercept: bool) {
        self.set_intercept(msr, true, intercept);
    }

}
```

## percpu

```rust

// (AMD64 APM Vol.2, Section 15.30.4)
//The 64-bit read/write VM_HSAVE_PA MSR holds the physical address of a 4KB block of memory where VMRUN saves host state
pub struct SvmPerCpuState<H: AxVCpuHal> {
    hsave_page: PhysFrame<H>,
}

impl<H: AxVCpuHal> AxArchPerCpu for SvmPerCpuState<H> {
    fn new(_cpu_id: usize) -> AxResult<Self> {
        Ok(Self {
            hsave_page: unsafe { PhysFrame::uninit() },
        })
    }

    /// Returns true if SVM is enabled on this core (EFER.SVME == 1)
    fn is_enabled(&self) -> bool {
        let efer = Msr::IA32_EFER.read();
        EferFlags::from_bits_truncate(efer).contains(EferFlags::SECURE_VIRTUAL_MACHINE_ENABLE)
    }

    fn hardware_enable(&mut self) -> AxResult {
        if !has_hardware_support() {
            return ax_err!(Unsupported, "CPU does not support AMD-SVM");
        }
        if self.is_enabled() {
            return ax_err!(ResourceBusy, "SVM already enabled");
        }

        // Enable XSAVE/XRSTOR.
        super::vcpu::XState::enable_xsave();

        // Allocate & register Host-Save Area
        self.hsave_page = PhysFrame::alloc_zero()?;
        let hsave_pa = self.hsave_page.start_paddr().as_usize() as u64;
        unsafe { Msr::VM_HSAVE_PA.write(hsave_pa); }


        //Set EFER.SVME to enable SVM
        let mut efer = EferFlags::from_bits_truncate(Msr::IA32_EFER.read());
        efer.insert(EferFlags::SECURE_VIRTUAL_MACHINE_ENABLE); // bit 12
        unsafe { Msr::IA32_EFER.write(efer.bits()); }

        info!("[AxVM] SVM enabled (HSAVE @ {:#x}).", hsave_pa);
        Ok(())
    }


    fn hardware_disable(&mut self) -> AxResult {
        if !self.is_enabled() {
            return ax_err!(BadState, "SVM is not enabled");
        }
        unsafe {
        // 1) Clear SVME bit
        let mut efer = EferFlags::from_bits_truncate(Msr::IA32_EFER.read());
        efer.remove(EferFlags::SECURE_VIRTUAL_MACHINE_ENABLE);
        Msr::IA32_EFER.write(efer.bits());

        // 2) Clear HSAVE pointer
        Msr::VM_HSAVE_PA.write(0);
    }
        info!("[AxVM] SVM disabled.");
        Ok(())
    }
}

```

## vcpu
``` rust

pub struct SvmVcpu<H: AxVCpuHal> {
    // DO NOT modify `guest_regs` and `host_stack_top` and their order unless you do know what you are doing!
    // DO NOT add anything before or between them unless you do know what you are doing!
    guest_regs: GeneralRegisters,
    host_stack_top: u64,
    launched: bool,
    vmcb: VmcbFrame<H>,
    iopm: IOPm<H>,
    msrpm: MSRPm<H>,
    pending_events: VecDeque<(u8, Option<u32>)>,
    xstate: XState,
    entry: Option<GuestPhysAddr>,
    npt_root: Option<HostPhysAddr>,
    // is_host: bool, temporary removed because we don't care about type 1.5 now
}

impl<H: AxVCpuHal> SvmVcpu<H> {
    /// Create a new [`SvmVcpu`].
    pub fn new() -> AxResult<Self> {
        let vcpu = Self {
            guest_regs: GeneralRegisters::default(),
            host_stack_top: 0,
            launched: false,
            vmcb:VmcbFrame::new()?,
            iopm: IOPm::passthrough_all()?,
            msrpm: MSRPm::passthrough_all()?,
            pending_events: VecDeque::with_capacity(8),
            xstate: XState::new(),
            entry: None,
            npt_root: None,
            // is_host: false,
        };
        info!("[HV] created SvmVcpu(vmcb: {:#x})", vcpu.vmcb.phys_addr());
        Ok(vcpu)
    }

    /// Set the new [`SvmVcpu`] context from guest OS.
    pub fn setup(&mut self, npt_root: HostPhysAddr, entry: GuestPhysAddr) -> AxResult {
        self.setup_vmcb(entry, npt_root)?;
        Ok(())
    }

    /// No operation is needed for SVM binding.
    ///
    /// Unlike VMX which requires VMCS to be loaded via VMPTRLD,
    /// SVM uses the `VMRUN` instruction and takes the VMCB physical address
    /// from the `RAX` register at the moment of execution.
    ///
    /// Since `RAX` is a volatile register and may be clobbered during normal execution,
    /// it is unsafe to set `RAX` earlier and rely on it later.
    /// Therefore, the correct place to set `RAX` is right before `VMRUN`,
    /// inside the actual launch/resume assembly code.
    ///
    /// This function is kept for interface consistency but performs no action.
    pub fn bind_to_current_processor(&self) -> AxResult {
        Ok(())
    }

    /// No operation is needed for SVM unbinding.
    ///
    /// SVM does not maintain a per-CPU binding state like VMX (e.g., via VMPTRLD).
    /// Once `VMEXIT` occurs, the VCPU state is saved to the VMCB, and no
    /// unbinding step is required.
    ///
    /// This function is kept for interface compatibility.
    pub fn unbind_from_current_processor(&self) -> AxResult {
        Ok(())
    }

    pub fn get_cpu_mode(&self) -> VmCpuMode {
        let vmcb = unsafe { self.vmcb.as_vmcb() }.state;

        let ia32_efer = vmcb.efer.get();
        let cs_attr = vmcb.cs.attr.get();
        let cr0 = vmcb.cr0.get();

        if (ia32_efer & (1 << 10)) != 0 {
            if (cs_attr & (1 << 13)) != 0 {
                // CS.L = 1
                VmCpuMode::Mode64
            } else {
                VmCpuMode::Compatibility
            }
        } else if (cr0 & (1 << 0)) != 0 {
            // CR0.PE = 1
            VmCpuMode::Protected
        } else {
            VmCpuMode::Real
        }
    }

    pub fn inner_run(&mut self) -> Option<SvmExitInfo> {
        // Inject pending events
        if self.launched {
            self.inject_pending_events().unwrap();
        }

        // Run guest
        self.load_guest_xstate();

        unsafe {
            self.svm_run();

        }

        self.load_host_xstate();

        // Handle vm-exits
        let exit_info = self.exit_info().unwrap();
        // debug!("VM exit: {:#x?}", exit_info);

        match self.builtin_vmexit_handler(&exit_info) {
            Some(result) => {
                if result.is_err() {
                    panic!(
                        "VmxVcpu failed to handle a VM-exit that should be handled by itself: {:?}, error {:?}, vcpu: {:#x?}",
                        exit_info.exit_info_1,
                        result.unwrap_err(),
                        self
                    );
                }
                None
            }
            None => Some(exit_info),
        }
    }

    pub fn exit_info(&self) -> AxResult<SvmExitInfo> {
        unsafe { self.vmcb.as_vmcb().exit_info() }
    }

    pub fn regs(&self) -> &GeneralRegisters {
        &self.guest_regs
    }

    pub fn regs_mut(&mut self) -> &mut GeneralRegisters {
        &mut self.guest_regs
    }
    pub fn gla2gva(&self, guest_rip: GuestVirtAddr) -> GuestVirtAddr {
        let vmcb = unsafe { self.vmcb.as_vmcb() };
        let cpu_mode = self.get_cpu_mode();
        let seg_base = if cpu_mode == VmCpuMode::Mode64 {
            0
        } else {
            vmcb.state.cs.base.get()
        };
        guest_rip + seg_base as usize
    }


    fn setup_vmcb(&mut self, entry: GuestPhysAddr, npt_root: HostPhysAddr) -> AxResult {
        self.bind_to_current_processor()?;
        self.setup_vmcb_guest(entry)?;
        self.setup_vmcb_control(npt_root, true)?;
        self.unbind_from_current_processor()?;
        Ok(())
    }


    fn setup_vmcb_guest(&mut self, entry: GuestPhysAddr) -> AxResult {
        info!("[AxVM] Setting up VMCB for guest at {:#x}", entry);
        let cr0_val: Cr0Flags =
            Cr0Flags::NOT_WRITE_THROUGH | Cr0Flags::CACHE_DISABLE | Cr0Flags::EXTENSION_TYPE;
        info!("here??????????????????");
        self.set_cr(0, cr0_val.bits());
        self.set_cr(4, 0);

        let st = unsafe { self.vmcb.as_vmcb() }.state;

        macro_rules! seg {
        ($seg:ident, $attr:expr) => {
            set_vmcb_segment(&mut st.$seg, 0, $attr);
        };
    }
        seg!(es, 0x93); seg!(cs, 0x9b); seg!(ss, 0x93); seg!(ds, 0x93);
        seg!(fs, 0x93); seg!(gs, 0x93); seg!(tr, 0x8b); seg!(ldtr, 0x82);

        // GDTR / IDTR
        st.gdtr.base.set(0);  st.gdtr.limit.set(0xffff);
        st.idtr.base.set(0);  st.idtr.limit.set(0xffff);

        // 关键寄存器与指针
        st.cr3.set(0);
        st.dr7.set(0x400);
        st.rsp.set(0);
        st.rip.set(entry.as_usize() as u64);
        st.rflags.set(0x2);                 // bit1 必须为 1
        st.dr6.set(0);                      // Pending-DBG-Exceptions 对应 0

        // SYSENTER MSRs
        st.sysenter_cs.set(0);
        st.sysenter_esp.set(0);
        st.sysenter_eip.set(0);

        // MSR / PAT / EFER
        st.efer.set(0 | EferFlags::SECURE_VIRTUAL_MACHINE_ENABLE.bits()); // 必须置 SVME 位
        st.g_pat.set(Msr::IA32_PAT.read());

        st.cpl.set(0);
        st.star.set(0);
        st.lstar.set(0);
        st.cstar.set(0);
        st.sfmask.set(0);
        st.kernel_gs_base.set(Msr::IA32_KERNEL_GSBASE.read());
        st.rax.set(0);                      // hypervisor 返回值

        Ok(())
    }

    fn setup_vmcb_control(&mut self, npt_root: HostPhysAddr, is_guest: bool) -> AxResult {
            let ct = unsafe { self.vmcb.as_vmcb() }.control;          // control-area 速记别名
            // ────────────────────────────────────────────────────────
            // 1) 基本运行环境：Nested Paging / ASID / Clean Bits / TLB
            // ────────────────────────────────────────────────────────

            // ① 开启 Nested Paging（AMD 对应 Intel 的 EPT）
            //    → set bit 0 of NESTED_CTL
            ct.nested_ctl.modify(NestedCtl::NP_ENABLE::SET);

            // ② guest ASID：NPT 使用的 TLB 标签
            ct.guest_asid.set(1);

            // ③ 嵌套 CR3（NPT root PA）
            ct.nested_cr3.set(npt_root.as_usize() as u64);

            // ④ Clean-Bits：0 = “全部脏” ⇒ 第一次 VMRUN 必定重新加载 save-area
            ct.clean_bits.set(0);

            // ⑤ TLB Control：0 = NONE, 1 = FLUSH-ASID, 3 = FLUSH-ALL
            ct.tlb_control.modify(VmcbTlbControl::FlushGuestTlb::SET);

            // ────────────────────────────────────────────────────────
            // 2) 选择要拦截的指令 / 事件
            //    （相当于 VMX 的 Pin-based / Primary / Secondary CTLS）
            // ────────────────────────────────────────────────────────

            use super::definitions::SvmIntercept;  // 你自己定义的枚举

            for intc in &[
                SvmIntercept::NMI,      // 非屏蔽中断
                SvmIntercept::CPUID,    // CPUID 指令
                SvmIntercept::SHUTDOWN, // HLT 时 Triple-Fault
                SvmIntercept::VMRUN,    // 来宾企图再次 VMRUN
                SvmIntercept::VMMCALL,  // Hypercall
                SvmIntercept::VMLOAD,
                SvmIntercept::VMSAVE,
                SvmIntercept::STGI,     // 设置全局中断
                SvmIntercept::CLGI,     // 清除全局中断
                SvmIntercept::SKINIT,   // 安全启动
            ] {
                ct.set_intercept(*intc);
            }
        Ok(())
    }
        // 如果你用 bitfield 方式，也可以：
        // ct.intercept_vector3.modify(InterceptVec3::NMI::SET + InterceptVec3::VINTR::SET);

    fn get_paging_level(&self) -> usize {
        todo!()
    }

}
// Implementaton for type1.5 hypervisor
// #[cfg(feature = "type1_5")]
impl<H: AxVCpuHal> SvmVcpu<H> {

    pub fn set_cr(&mut self, cr_idx: usize, val: u64) -> AxResult {
        let mut vmcb = unsafe { self.vmcb.as_vmcb() };
        info!("here??????????????????");

        match cr_idx {
            0 => vmcb.state.cr0.set(val),
            3 => vmcb.state.cr3.set(val),
            4 => vmcb.state.cr4.set(val),
            _ => return ax_err!(InvalidInput, format_args!("Unsupported CR{}", cr_idx)),
        }

        Ok(())
    }
    #[allow(dead_code)]
    fn cr(&self, cr_idx: usize) -> usize {
        let mut vmcb = unsafe { self.vmcb.as_vmcb() };
        (|| -> AxResult<usize> {
            Ok(match cr_idx {
                0 => vmcb.state.cr0.get() as usize,
                3 => vmcb.state.cr3.get() as usize,
                4 => vmcb.state.cr4.get() as usize,
                _ => unreachable!(),
            })
        })()
            .expect("Failed to read guest control register")
    }
}

impl<H: AxVCpuHal> SvmVcpu<H> {

    //  unsafe extern "C" fn svm_run(&mut self) -> usize {
    //     let vmcb_phy = self.vmcb.phys_addr().as_usize() as u64;
    //
    //      unsafe {
    //         naked_asm!(
    //             save_regs_to_stack!(),
    //             // "clgi",                                // 清除中断，确保 SVM 运行不中断
    //             "mov    [rdi + {host_stack_size}], rsp", // save current RSP to Vcpu::host_stack_top
    //             "mov    rsp, rdi",                      // set RSP to guest regs area
    //             restore_regs_from_stack!(),            // restore guest status
    //             "mov rax,{vmcb}",
    //             "vmload rax",
    //             "vmrun rax",
    //             "jmp {failed}",
    //             host_stack_size = const size_of::<GeneralRegisters>(),
    //             failed = sym Self::svm_entry_failed,
    //             vmcb = in(reg) vmcb_phy,  // 正确绑定 vmcb 变量
    //             // options(noreturn),
    //         );
    //     }
    //      0
    // }

    pub unsafe fn svm_run(&mut self) -> usize {
        let vmcb = self.vmcb.phys_addr().as_usize() as u64;
        let guest_regs = self.regs_mut();
        // panic!("{:x}",vmcb);
        // panic!("SVM run not implemented yet");
        asm!(
        // "clgi",
        "mov rax, {0}",
        "vmload rax",
        "vmrun rax",
        // "call {entry}",
        // in(reg) guest_regs,
        in(reg) vmcb,
        // entry = sym Self::svm_entry,
        options(noreturn),
        );
    }

    #[naked]
    unsafe extern "C" fn svm_entry() -> ! {
        naked_asm!(
            "ud2",
        // "mov [rdi + {host_stack_size}], rsp",
        // "mov rsp, rdi",
        // // restore_regs_from_stack!(),
        // "vmload rax",
        // "vmrun rax",
        "jmp {failed}",
        // host_stack_size = const size_of::<GeneralRegisters>(),
        failed = sym Self::svm_entry_failed,
    )
    }



    #[naked]
    /// Return after vm-exit.
    ///
    /// The return value is a dummy value.
    unsafe extern "C" fn svm_exit(&mut self) -> usize {
        unsafe {
            naked_asm!(
                save_regs_to_stack!(),                  // save guest status
                "mov    rsp, [rsp + {host_stack_top}]", // set RSP to Vcpu::host_stack_top
                restore_regs_from_stack!(),             // restore host status
                "ret",
                host_stack_top = const size_of::<GeneralRegisters>(),
            );
        }

    }

    fn builtin_vmexit_handler(&mut self, exit_info: &SvmExitInfo) -> Option<AxResult> {
        let exit_code = match exit_info.exit_code {
            Ok(code) => code,
            Err(code) => {
                error!("Unknown #VMEXIT exit code: {:#x}", code);
                panic!("wrong code");
            }
        };

        match exit_code {
            SvmExitCode::CPUID => Some(self.handle_cpuid()),
            _ => None,
        }

        //
        // let res = match exit_code {
        //     SvmExitCode::EXCP(vec) => self.handle_exception(vec, &exit_info),
        //     SvmExitCode::NMI => self.handle_nmi(),
        //     SvmExitCode::CPUID => self.handle_cpuid(),
        //     SvmExitCode::VMMCALL => self.handle_hypercall(),
        //     SvmExitCode::NPF => self.handle_nested_page_fault(&exit_info),
        //     SvmExitCode::MSR => match exit_info.exit_info_1 {
        //         0 => self.handle_msr_read(),
        //         1 => self.handle_msr_write(),
        //         _ => panic!("MSR can't handle"),
        //     },
        //     SvmExitCode::SHUTDOWN => {
        //         error!("#VMEXIT(SHUTDOWN): {:#x?}", exit_info);
        //         self.cpu_data.vcpu.inject_fault()?;
        //         Ok(())
        //     }
        //     _ => panic!("code can't handle"),
        // };
    }
    fn setup(&mut self, _config: Self::SetupConfig) -> AxResult {
        self.setup_vmcb(self.entry.unwrap(), self.npt_root.unwrap())
    }

    fn run(&mut self) -> AxResult<AxVCpuExitReason> {
        match self.inner_run() {
                Some(exit_info) => {
                warn!("VMX unsupported VM-Exit: {:#x?}",exit_info.exit_info_1);
                warn!("VCpu {:#x?}", self);
                Ok(AxVCpuExitReason::Halt)
            }
            _ => Ok(AxVCpuExitReason::Halt)
        }
    }

    fn bind(&mut self) -> AxResult {
        self.bind_to_current_processor()
    }

    fn unbind(&mut self) -> AxResult {
        self.launched = false;
        self.unbind_from_current_processor()
    }

    fn set_gpr(&mut self, reg: usize, val: usize) {
        self.regs_mut().set_reg_of_index(reg as u8, val as u64);
    }
}
```
