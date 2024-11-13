 .section ".rodata"


# load bpf_prgm_redirect_userspace a658699d4009ed41f0bfbb8f2cf768c7
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
