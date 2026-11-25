// Win64 ABI regression helper.
//
// Verifies that a callee preserves XMM6-XMM15, which are nonvolatile under the
// Microsoft x64 ABI. The callee is passed through an indirect call so CFG
// builds also exercise the guard check. All ten registers are set to distinct
// patterns, the call is made, and the patterns are compared afterwards.
//
// System V assembler syntax; assemble with x86_64-w64-mingw32-gcc.
    .text
    .globl sirus_abi_xmm_check
    .def sirus_abi_xmm_check; .scl 2; .type 32; .endef
    .seh_proc sirus_abi_xmm_check
sirus_abi_xmm_check:
    subq $328, %rsp
    .seh_stackalloc 328
    .seh_savexmm %xmm6, 0
    .seh_savexmm %xmm7, 16
    .seh_savexmm %xmm8, 32
    .seh_savexmm %xmm9, 48
    .seh_savexmm %xmm10, 64
    .seh_savexmm %xmm11, 80
    .seh_savexmm %xmm12, 96
    .seh_savexmm %xmm13, 112
    .seh_savexmm %xmm14, 128
    .seh_savexmm %xmm15, 144
    .seh_endprologue

    movdqu %xmm6, 0(%rsp)
    movdqu %xmm7, 16(%rsp)
    movdqu %xmm8, 32(%rsp)
    movdqu %xmm9, 48(%rsp)
    movdqu %xmm10, 64(%rsp)
    movdqu %xmm11, 80(%rsp)
    movdqu %xmm12, 96(%rsp)
    movdqu %xmm13, 112(%rsp)
    movdqu %xmm14, 128(%rsp)
    movdqu %xmm15, 144(%rsp)

    leaq sirus_abi_patterns(%rip), %rax
    movdqu 0(%rax), %xmm6
    movdqu 16(%rax), %xmm7
    movdqu 32(%rax), %xmm8
    movdqu 48(%rax), %xmm9
    movdqu 64(%rax), %xmm10
    movdqu 80(%rax), %xmm11
    movdqu 96(%rax), %xmm12
    movdqu 112(%rax), %xmm13
    movdqu 128(%rax), %xmm14
    movdqu 144(%rax), %xmm15

    movq %rcx, %rax
    movq %rdx, %rcx
    movq %r8, %rdx
    call *%rax

    leaq sirus_abi_patterns(%rip), %rax
    xorl %r10d, %r10d
    movdqu 0(%rax), %xmm0
    pcmpeqb %xmm0, %xmm6
    pmovmskb %xmm6, %ecx
    cmpl $0xffff, %ecx
    setne %cl
    movzbl %cl, %ecx
    orl %ecx, %r10d
    movdqu 16(%rax), %xmm0
    pcmpeqb %xmm0, %xmm7
    pmovmskb %xmm7, %ecx
    cmpl $0xffff, %ecx
    setne %cl
    movzbl %cl, %ecx
    orl %ecx, %r10d
    movdqu 32(%rax), %xmm0
    pcmpeqb %xmm0, %xmm8
    pmovmskb %xmm8, %ecx
    cmpl $0xffff, %ecx
    setne %cl
    movzbl %cl, %ecx
    orl %ecx, %r10d
    movdqu 48(%rax), %xmm0
    pcmpeqb %xmm0, %xmm9
    pmovmskb %xmm9, %ecx
    cmpl $0xffff, %ecx
    setne %cl
    movzbl %cl, %ecx
    orl %ecx, %r10d
    movdqu 64(%rax), %xmm0
    pcmpeqb %xmm0, %xmm10
    pmovmskb %xmm10, %ecx
    cmpl $0xffff, %ecx
    setne %cl
    movzbl %cl, %ecx
    orl %ecx, %r10d
    movdqu 80(%rax), %xmm0
    pcmpeqb %xmm0, %xmm11
    pmovmskb %xmm11, %ecx
    cmpl $0xffff, %ecx
    setne %cl
    movzbl %cl, %ecx
    orl %ecx, %r10d
    movdqu 96(%rax), %xmm0
    pcmpeqb %xmm0, %xmm12
    pmovmskb %xmm12, %ecx
    cmpl $0xffff, %ecx
    setne %cl
    movzbl %cl, %ecx
    orl %ecx, %r10d
    movdqu 112(%rax), %xmm0
    pcmpeqb %xmm0, %xmm13
    pmovmskb %xmm13, %ecx
    cmpl $0xffff, %ecx
    setne %cl
    movzbl %cl, %ecx
    orl %ecx, %r10d
    movdqu 128(%rax), %xmm0
    pcmpeqb %xmm0, %xmm14
    pmovmskb %xmm14, %ecx
    cmpl $0xffff, %ecx
    setne %cl
    movzbl %cl, %ecx
    orl %ecx, %r10d
    movdqu 144(%rax), %xmm0
    pcmpeqb %xmm0, %xmm15
    pmovmskb %xmm15, %ecx
    cmpl $0xffff, %ecx
    setne %cl
    movzbl %cl, %ecx
    orl %ecx, %r10d

    movdqu 0(%rsp), %xmm6
    movdqu 16(%rsp), %xmm7
    movdqu 32(%rsp), %xmm8
    movdqu 48(%rsp), %xmm9
    movdqu 64(%rsp), %xmm10
    movdqu 80(%rsp), %xmm11
    movdqu 96(%rsp), %xmm12
    movdqu 112(%rsp), %xmm13
    movdqu 128(%rsp), %xmm14
    movdqu 144(%rsp), %xmm15
    addq $328, %rsp
    movl %r10d, %eax
    ret
    .seh_endproc

    .section .rdata,"dr"
    .p2align 4
sirus_abi_patterns:
    .quad 0x0606060606060606, 0x1616161616161616
    .quad 0x0707070707070707, 0x1717171717171717
    .quad 0x0808080808080808, 0x1818181818181818
    .quad 0x0909090909090909, 0x1919191919191919
    .quad 0x0a0a0a0a0a0a0a0a, 0x1a1a1a1a1a1a1a1a
    .quad 0x0b0b0b0b0b0b0b0b, 0x1b1b1b1b1b1b1b1b
    .quad 0x0c0c0c0c0c0c0c0c, 0x1c1c1c1c1c1c1c1c
    .quad 0x0d0d0d0d0d0d0d0d, 0x1d1d1d1d1d1d1d1d
    .quad 0x0e0e0e0e0e0e0e0e, 0x1e1e1e1e1e1e1e1e
    .quad 0x0f0f0f0f0f0f0f0f, 0x1f1f1f1f1f1f1f1f
