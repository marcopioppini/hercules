 .section ".rodata"


# load bpf_prgm_redirect_userspace 547691a10d344c02d8cb0e437f1b0e09
 .globl bpf_prgm_redirect_userspace
 .type bpf_prgm_redirect_userspace, STT_OBJECT
 .globl bpf_prgm_redirect_userspace_size
 .type bpf_prgm_redirect_userspace_size, STT_OBJECT
bpf_prgm_redirect_userspace:
 .incbin "bpf_prgm/redirect_userspace.o"
 .byte 0
 .size bpf_prgm_redirect_userspace, .-bpf_prgm_redirect_userspace
bpf_prgm_redirect_userspace_size:
 .int (.-bpf_prgm_redirect_userspace-1)
