#if defined(__AVR__)

.text

.global sha1_rotl5
.type sha1_rotl5, @function
sha1_rotl5:
    ; Input/output in r25:r22.
    ; r20 is call-clobbered on AVR-GCC, so it can be used as scratch.
    clr r20

    lsl r22
    rol r23
    rol r24
    rol r25
    rol r20

    lsl r22
    rol r23
    rol r24
    rol r25
    rol r20

    lsl r22
    rol r23
    rol r24
    rol r25
    rol r20

    lsl r22
    rol r23
    rol r24
    rol r25
    rol r20

    lsl r22
    rol r23
    rol r24
    rol r25
    rol r20

    or r22, r20
    ret
.size sha1_rotl5, .-sha1_rotl5

.global sha1_rotl30
.type sha1_rotl30, @function
sha1_rotl30:
    ; ROTL30 is the same as ROTR2.
    mov  r20, r22
    andi r20, 0x03
    lsl  r20
    lsl  r20
    lsl  r20
    lsl  r20
    lsl  r20
    lsl  r20

    lsr  r25
    ror  r24
    ror  r23
    ror  r22

    lsr  r25
    ror  r24
    ror  r23
    ror  r22

    or   r25, r20
    ret
.size sha1_rotl30, .-sha1_rotl30

#endif
