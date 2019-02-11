    .global ctcert
    .global ctcert_size
    .section .rodata
ctcert:
    .incbin "ctcert.d"
1:
ctcert_size:
    .int 1b - ctcert
