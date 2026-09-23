TITLE "Module C: DES 16-Round Feistel Core Engine"

.386
.model flat, stdcall

INCLUDE Irvine32.inc

.data
        ; Initial Permutation
        IP_Table BYTE 58, 50, 42, 34, 26, 18, 10, 2
                 BYTE 60, 52, 44, 36, 28, 20, 12, 4
                 BYTE 62, 54, 46, 38, 30, 22, 14, 6
                 BYTE 64, 56, 48, 40, 32, 24, 16, 8
                 BYTE 57, 49, 41, 33, 25, 17,  9, 1
                 BYTE 59, 51, 43, 35, 27, 19, 11, 3
                 BYTE 61, 53, 45, 37, 29, 21, 13, 5
                 BYTE 63, 55, 47, 39, 31, 23, 15, 7

        ; Inverse Initial Permutation (IP^-1)
        IP_Inv_Table    BYTE 40,  8, 48, 16, 56, 24, 64, 32
                        BYTE 39,  7, 47, 15, 55, 23, 63, 31
                        BYTE 38,  6, 46, 14, 54, 22, 62, 30
                        BYTE 37,  5, 45, 13, 53, 21, 61, 29
                        BYTE 36,  4, 44, 12, 52, 20, 60, 28
                        BYTE 35,  3, 43, 11, 51, 19, 59, 27
                        BYTE 34,  2, 42, 10, 50, 18, 58, 26
                        BYTE 33,  1, 41,  9, 49, 17, 57, 25
        
        ; Expansion Tabl
        E_Table BYTE 32,  1,  2,  3,  4,  5
                BYTE  4,  5,  6,  7,  8,  9
                BYTE  8,  9, 10, 11, 12, 13
                BYTE 12, 13, 14, 15, 16, 17
                BYTE 16, 17, 18, 19, 20, 21
                BYTE 20, 21, 22, 23, 24, 25
                BYTE 24, 25, 26, 27, 28, 29
                BYTE 28, 29, 30, 31, 32, 1


; Primitive functions for the Data Encryption Standard.
        ; Permutaion
        P_Table BYTE 16,  7, 20, 21
                BYTE 29, 12, 28, 17
                BYTE  1, 15, 23, 26
                BYTE  5, 18, 31, 10
                BYTE  2,  8, 24, 14
                BYTE 32, 27,  3,  9
                BYTE 19, 13, 30,  6
                BYTE 22, 11,  4, 25

        S_Box1  BYTE 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7
                BYTE 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8
                BYTE 4, 1, 14, 8, 13, 6, 2,11 ,15 ,12 ,9 ,7 ,3 ,10 ,5 ,0
                BYTE 15 ,12 ,8 ,2 ,4 ,9 ,1 ,7 ,5 ,11 ,3 ,14 ,10 ,0 ,6 ,13
        S_Box2  BYTE 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10
                BYTE 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5
                BYTE 0 ,14 ,7 ,11 ,10 ,4 ,13 ,1 ,5 ,8 ,12 ,6 ,9 ,3 ,2 ,15
                BYTE 13 ,8 ,10 ,1 ,3 ,15 ,4 ,2 ,11 ,6 ,7 ,12 ,0 ,5 ,14 ,9
        S_Box3  BYTE 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8
                BYTE 13 ,7 ,0 ,9 ,3 ,4 ,6 ,10 ,2 ,8 ,5 ,14 ,12 ,11 ,15 ,1
                BYTE 13 ,6 ,4 ,9 ,8 ,15 ,3 ,0 ,11 ,1 ,2 ,12 ,5 ,10 ,14 ,7
                BYTE 1 ,10 ,13 ,0 ,6 ,9 ,8 ,7 ,4 ,15 ,14 ,3 ,11 ,5 ,2 ,12
        S_Box4  BYTE 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15
                BYTE 13 ,8 ,11 ,5 ,6 ,15 ,0 ,3 ,4 ,7 ,2 ,12 ,1 ,10 ,14 ,9
                BYTE 10 ,6 ,9 ,0 ,12 ,11 ,7 ,13 ,15 ,1 ,3 ,14 ,5 ,2 ,8 ,4
                BYTE 3 ,15 ,0 ,6 ,10 ,1 ,13 ,8 ,9 ,4 ,5 ,11 ,12 ,7 ,2 ,14
        S_Box5  BYTE 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9
                BYTE 14 ,11 ,2 ,12 ,4 ,7 ,13 ,1 ,5 ,0 ,15 ,10 ,3 ,9 ,8 ,6
                BYTE 4 ,2 ,1 ,11 ,10 ,13 ,7 ,8 ,15 ,9 ,12 ,5 ,6 ,3 ,0 ,14
                BYTE 11 ,8 ,12 ,7 ,1 ,14 ,2 ,13 ,6 ,15 ,0 ,9 ,10 ,4 ,5 ,3
        S_Box6  BYTE 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11
                BYTE 10 ,15 ,4 ,2 ,7 ,12 ,9 ,5 ,6 ,1 ,13 ,14 ,0 ,11 ,3 ,8
                BYTE 9 ,14 ,15 ,5 ,2 ,8 ,12 ,3 ,7 ,0 ,4 ,10 ,1 ,13 ,11 ,6
                BYTE 4 ,3 ,2 ,12 ,9 ,5 ,15 ,10 ,11 ,14 ,1 ,7 ,6 ,0 ,8, 13
        S_Box7  BYTE 4, 11, 2, 14, 15, 0, 8, 13, 3, 7, 9, 5, 6, 10, 12, 1
                BYTE 13 ,0 ,11 ,7 ,4 ,9 ,1 ,10 ,14 ,3 ,5 ,12 ,2 ,15 ,8 ,6
                BYTE 1 ,4 ,11 ,13 ,12 ,3 ,7 ,14 ,10 ,15 ,6 ,8 ,0 ,5 ,9 ,2
                BYTE 6 ,11 ,13 ,8 ,1 ,4 ,10 ,7 ,9 ,5 ,0 ,15 ,14 ,2 ,3 ,12
        S_Box8  BYTE 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7
                BYTE 1 ,15 ,13 ,8 ,10 ,3 ,7 ,4 ,12 ,5 ,6 ,11 ,0 ,14 ,9 ,2
                BYTE 7 ,11 ,4 ,1 ,9 ,12 ,14 ,2 ,0 ,6 ,10 ,13 ,15 ,3 ,5 ,8
                BYTE 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 
                
.code

; Disable automatic stack frames
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

ProcessDES PROC pDataBlock:PTR BYTE, pKeySchedule:PTR BYTE

; reviw the stack frame and registers used in this again
        push ebp
        mov ebp, esp

        push ebx        ;manual counter instead of using ecx
        push ecx        ;l
        push esi
        push edi        ;r

; scramble the input with the IP
        mov esi, [ebp + 8]
        xor ebx, ebx

        xor ecx, ecx
        xor edi, edi

IP_Scramble:
        cmp ebx, 64
        jae IP_Scramble_Done

        xor eax, eax
        movzx eax, BYTE PTR IP_Table[ebx]
        sub eax, 1

        push ecx

        xor edx, edx
        mov ecx, 8
        div ecx

        movzx eax, BYTE PTR [esi + eax]

        ; check how much to shift 7 - Bit Offset
        mov ecx, 7
        sub ecx, edx
        shr eax, cl     
        and eax, 1

        pop ecx

; fill the left and right | ECX:EDI
        cmp ebx, 32
        jb Pack_Left 

        ; pack rigjt edi
        shl edi, 1      ; shift rihgt half
        or edi, eax     ; Insert bit into right half
        jmp Pack_Done

        Pack_Left:
                ;pack left ecx
                shl ecx, 1      ; shift left half
                or ecx, eax     ; insert bit into lrft half

        Pack_Done:
                inc ebx
                jmp IP_Scramble

IP_Scramble_Done:
        xor ebx, ebx    ; round counter
        xor eax, eax    ; eax -> lower 32
        xor edx, edx    ; edx -> upper 16 

Feistel_Round:
        cmp ebx, 16
        jae Feistel_Done

        push ebx
        xor ebx, ebx
; Expansion
        Expansion_Loop:
                cmp ebx, 48
                jae Expansion_Done

                xor ecx, ecx
                movzx ecx, BYTE PTR E_Table[ebx]
                sub ecx, 1

                ; 31 - ecx
                mov esi, 31
                sub esi, ecx
                mov ecx, esi

                mov esi, edi    
                shr esi, cl     
                and esi, 1

                shl eax, 1      ; shift lower 32 bits left 
                rcl edx, 1      ; shift upper 16 bits left 
                
                or eax, esi

                inc ebx
                jmp Expansion_Loop

        Expansion_Done:
                pop ebx

; subkey
        lea esi, [ebx + ebx*2]  ; esi = ebx * 3
        add esi, esi            ; esi = esi * 2 
        
        add esi, [ebp + 12]     ; + Base Pointer of Key Schedule from Stack
        
        mov ebx, DWORD PTR [esi+2]      ; subkey bit17-48 (4 ไบต์หลัง)
        bswap ebx
        xor eax, ebx

        mov cx, WORD PTR [esi]  ; subkey bit1-16 (2 ไบต์แรก)
        xchg ch, cl     ; สลับ byte ให้เป็น natural form
        xor dx, cx
        
; S-box
        push ebx 
        push ecx 
        push edi    
        
        xor edi, edi
        
;s box 1
        movzx ecx, dx   ; (upper 16 bits) 
        shr ecx, 10
        and ecx, 3Fh    ; only 6 low bits 

        mov esi, ecx
        shr esi, 4
        and esi, 2
        
        mov ebx, ecx
        and ebx, 1 
        or esi, ebx 

        mov ebx, ecx
        shr ebx, 1 
        and ebx, 0Fh 

        shl esi, 4
        add esi, ebx    
        
        movzx ebx, BYTE PTR S_Box1[esi]        ; fetch form the table
        
        shl ebx, 28     ; move to left (bit 31-28) 
        or edi, ebx

;s box 2
        movzx ecx, dx
        shr ecx, 4
        and ecx, 3Fh 

        mov esi, ecx
        shr esi, 4
        and esi, 2

        mov ebx, ecx
        and ebx, 1 
        or esi, ebx 

        mov ebx, ecx
        shr ebx, 1 
        and ebx, 0Fh 

        shl esi, 4
        add esi, ebx    
        
        movzx ebx, BYTE PTR S_Box2[esi]   
        
        shl ebx, 24
        or edi, ebx

;s box 3
        movzx ecx, dx
        and ecx, 0Fh 
        shl ecx, 2      ;
        mov esi, eax
        shr esi, 30 
        or ecx, esi 

        mov esi, ecx
        shr esi, 4
        and esi, 2
        mov ebx, ecx
        and ebx, 1
        or esi, ebx         ; esi = row

        mov ebx, ecx
        shr ebx, 1
        and ebx, 0Fh        ; ebx = column

        shl esi, 4
        add esi, ebx
        movzx ebx, BYTE PTR S_Box3[esi]
        
        shl ebx, 20 
        or edi, ebx

; s box 4
        mov ecx, eax
        shr ecx, 24     ;
        and ecx, 3Fh

        mov esi, ecx
        shr esi, 4
        and esi, 2
        mov ebx, ecx
        and ebx, 1
        or esi, ebx 

        mov ebx, ecx
        shr ebx, 1
        and ebx, 0Fh 

        shl esi, 4
        add esi, ebx
        movzx ebx, BYTE PTR S_Box4[esi]
        
        shl ebx, 16 
        or edi, ebx

; s box 5
        mov ecx, eax
        shr ecx, 18     ;
        and ecx, 3Fh

        mov esi, ecx
        shr esi, 4
        and esi, 2
        mov ebx, ecx
        and ebx, 1
        or esi, ebx 

        mov ebx, ecx
        shr ebx, 1
        and ebx, 0Fh 

        shl esi, 4
        add esi, ebx
        movzx ebx, BYTE PTR S_Box5[esi]
        
        shl ebx, 12
        or edi, ebx

; s box 6
        mov ecx, eax
        shr ecx, 12     ;
        and ecx, 3Fh

        mov esi, ecx
        shr esi, 4
        and esi, 2
        mov ebx, ecx
        and ebx, 1
        or esi, ebx 

        mov ebx, ecx
        shr ebx, 1
        and ebx, 0Fh 

        shl esi, 4      ;
        add esi, ebx
        movzx ebx, BYTE PTR S_Box6[esi]
        
        shl ebx, 8
        or edi, ebx

; s box 7
        mov ecx, eax
        shr ecx, 6     ;
        and ecx, 3Fh

        mov esi, ecx
        shr esi, 4
        and esi, 2
        mov ebx, ecx
        and ebx, 1
        or esi, ebx 

        mov ebx, ecx
        shr ebx, 1
        and ebx, 0Fh 

        shl esi, 4      ;
        add esi, ebx
        movzx ebx, BYTE PTR S_Box7[esi]
        
        shl ebx, 4      ;
        or edi, ebx

; s box 8
        mov ecx, eax
        and ecx, 3Fh

        mov esi, ecx
        shr esi, 4
        and esi, 2
        mov ebx, ecx
        and ebx, 1
        or esi, ebx 

        mov ebx, ecx
        shr ebx, 1
        and ebx, 0Fh 

        shl esi, 4
        add esi, ebx
        movzx ebx, BYTE PTR S_Box8[esi]

        or edi, ebx

; Permutation
        mov eax, edi
        pop edi
        pop ecx
        pop ebx

        ; 32 loop
        push ebx
        xor ebx, ebx 
        xor edx, edx

Permutation_Loop:
        cmp ebx, 32 
        jae Permutation_Done

        push ecx 
        xor ecx, ecx
        movzx ecx, BYTE PTR P_Table[ebx]
        sub ecx, 1 

        push esi 
        mov esi, 31
        sub esi, ecx
        mov ecx, esi 
        pop esi

        mov esi, eax 
        shr esi, cl
        and esi, 1 

        shl edx, 1  
        or edx, esi 

        pop ecx 

        inc ebx
        jmp Permutation_Loop

Permutation_Done:
        pop ebx

; cross-xor then swap
        xor ecx, edx 
        xchg ecx, edi  

        inc ebx
        jmp Feistel_Round


Feistel_Done:
        mov esi, [ebp + 8] 
        push esi         
        
        xor esi, esi       
        xor edx, edx        
        
        push ebx
        xor ebx, ebx   
        
IP_Inv_Loop:
        cmp ebx, 64
        jae IP_Inv_Done

        xor eax, eax
        movzx eax, BYTE PTR IP_Inv_Table[ebx]
        sub eax, 1

        cmp eax, 32
        jb Extract_EDI
        
        push ecx
        push edx
        sub eax, 32
        mov edx, 31
        sub edx, eax
        xchg edx, ecx  
        shr edx, cl
        and edx, 1
        mov eax, edx
        pop edx
        pop ecx
        jmp Append_Bit

Extract_EDI:
        push edi
        push ecx
        push edx
        mov edx, 31
        sub edx, eax
        mov ecx, edx
        shr edi, cl
        and edi, 1
        mov eax, edi 
        pop edx
        pop ecx
        pop edi

Append_Bit:
        cmp ebx, 32
        jb Pack_EDX
        shl esi, 1
        or esi, eax
        jmp Loop_End
Pack_EDX:
        shl edx, 1
        or edx, eax
Loop_End:
        inc ebx
        jmp IP_Inv_Loop

IP_Inv_Done:
        pop ebx 
        pop eax 
        
        bswap edx 
        mov [eax], edx
        bswap esi
        mov [eax + 4], esi

        pop edi
        pop esi
        pop ecx
        pop ebx

        pop ebp
        ret 8

ProcessDES ENDP

OPTION PROLOGUE:PrologueDef
OPTION EPILOGUE:EpilogueDef

