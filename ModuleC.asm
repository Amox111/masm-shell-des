TITLE "Module C: DES 16-Round Feistel Core Engine"

.386
.model flat, stdcall
.stack 4096

INCLUDE Irvine32.inc

.data
        ; Initial Permutation (IP) Table - 64 bytes
        IP_Table BYTE 58, 50, 42, 34, 26, 18, 10, 2
                 BYTE 60, 52, 44, 36, 28, 20, 12, 4
                 BYTE 62, 54, 46, 38, 30, 22, 14, 6
                 BYTE 64, 56, 48, 40, 32, 24, 16, 8
                 BYTE 57, 49, 41, 33, 25, 17,  9, 1
                 BYTE 59, 51, 43, 35, 27, 19, 11, 3
                 BYTE 61, 53, 45, 37, 29, 21, 13, 5
                 BYTE 63, 55, 47, 39, 31, 23, 15, 7

        ; Inverse Initial Permutation (IP^-1) Table - 64 bytes
        IP_Inv_Table    BYTE 40,  8, 48, 16, 56, 24, 64, 32
                        BYTE 39,  7, 47, 15, 55, 23, 63, 31
                        BYTE 38,  6, 46, 14, 54, 22, 62, 30
                        BYTE 37,  5, 45, 13, 53, 21, 61, 29
                        BYTE 36,  4, 44, 12, 52, 20, 60, 28
                        BYTE 35,  3, 43, 11, 51, 19, 59, 27
                        BYTE 34,  2, 42, 10, 50, 18, 58, 26
                        BYTE 33,  1, 41,  9, 49, 17, 57, 25

        E_Table BYTE 32,  1,  2,  3,  4,  5
                BYTE  4,  5,  6,  7,  8,  9
                BYTE  8,  9, 10, 11, 12, 13
                BYTE 12, 13, 14, 15, 16, 17
                BYTE 16, 17, 18, 19, 20, 21
                BYTE 20, 21, 22, 23, 24, 25
                BYTE 24, 25, 26, 27, 28, 29
                BYTE 28, 29, 30, 31, 32, 1


; RIMITIVE FUNCTIONS FOR THE DATA ENCRYPTION ALGORITHM
        P_Table BYTE 16,  7, 20, 21
                BYTE 29, 12, 28, 17
                BYTE  1, 15, 23, 26
                BYTE  5, 18, 31, 10
                BYTE  2,  8, 24, 14
                BYTE 32, 27,  3,  9
                BYTE 19, 13, 30,  6
                BYTE 22, 11,  4, 25

        S_BoxS1 BYTE 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7
                BYTE 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8
                BYTE 4, 1, 14, 8, 13, 6, 2,11 ,15 ,12 ,9 ,7 ,3 ,10 ,5 ,0
                BYTE 15 ,12 ,8 ,2 ,4 ,9 ,1 ,7 ,5 ,11 ,3 ,14 ,10 ,0 ,6 ,13
        S_BoxS2 BYTE 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10
                BYTE 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5
                BYTE 0 ,14 ,7 ,11 ,10 ,4 ,13 ,1 ,5 ,8 ,12 ,6 ,9 ,3 ,2 ,15
                BYTE 13 ,8 ,10 ,1 ,3 ,15 ,4 ,2 ,11 ,6 ,7 ,12 ,0 ,5 ,14 ,9
        S_BoxS3 BYTE 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8
                BYTE 13 ,7 ,0 ,9 ,3 ,4 ,6 ,10 ,2 ,8 ,5 ,14 ,12 ,11 ,15 ,1
                BYTE 13 ,6 ,4 ,9 ,8 ,15 ,3 ,0 ,11 ,1 ,2 ,12 ,5 ,10 ,14 ,7
                BYTE 1 ,10 ,13 ,0 ,6 ,9 ,8 ,7 ,4 ,15 ,14 ,3 ,11 ,5 ,2 ,12
        S_BoxS4 BYTE 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15
                BYTE 13 ,8 ,11 ,5 ,6 ,15 ,0 ,3 ,4 ,7 ,2 ,12 ,1 ,10 ,14 ,9
                BYTE 10 ,6 ,9 ,0 ,12 ,11 ,7 ,13 ,15 ,1 ,3 ,14 ,5 ,2 ,8 ,4
                BYTE 3 ,15 ,0 ,6 ,10 ,1 ,13 ,8 ,9 ,4 ,5 ,11 ,12 ,7 ,2 ,14
        S_BoxS5 BYTE 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9
                BYTE 14 ,11 ,2 ,12 ,4 ,7 ,13 ,1 ,5 ,0 ,15 ,10 ,3 ,9 ,8 ,6
                BYTE 4 ,2 ,1 ,11 ,10 ,13 ,7 ,8 ,15 ,9 ,12 ,5 ,6 ,3 ,0 ,14
                BYTE 11 ,8 ,12 ,7 ,1 ,14 ,2 ,13 ,6 ,15 ,0 ,9 ,10 ,4 ,5 ,3
        S_BoxS6 BYTE 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11
                BYTE 10 ,15 ,4 ,2 ,7 ,12 ,9 ,5 ,6 ,1 ,13 ,14 ,0 ,11 ,3 ,8
                BYTE 9 ,14 ,15 ,5 ,2 ,8 ,12 ,3 ,7 ,0 ,4 ,10 ,1 ,13 ,11 ,6
                BYTE 4 ,3 ,2 ,12 ,9 ,5 ,15 ,10 ,11 ,14 ,1 ,7 ,6 ,0 ,8, 13
        S_BoxS7 BYTE 4, 11, 2, 14, 15, 0, 8, 13, 3, 7, 9, 5, 6, 10, 12, 1
                BYTE 13 ,0 ,11 ,7 ,4 ,9 ,1 ,10 ,14 ,3 ,5 ,12 ,2 ,15 ,8 ,6
                BYTE 1 ,4 ,11 ,13 ,12 ,3 ,7 ,14 ,10 ,15 ,6 ,8 ,0 ,5 ,9 ,2
                BYTE 6 ,11 ,13 ,8 ,1 ,4 ,10 ,7 ,9 ,5 ,0 ,15 ,14 ,2 ,3 ,12
        S_BoxS8 BYTE 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7
                BYTE 1 ,15 ,13 ,8 ,10 ,3 ,7 ,4 ,12 ,5 ,6 ,11 ,0 ,14 ,9 ,2
                BYTE 7 ,11 ,4 ,1 ,9 ,12 ,14 ,2 ,0 ,6 ,10 ,13 ,15 ,3 ,5 ,8
                BYTE 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 
         


; Input -> scramble IP -> 16 rounds of Feistel -> scramble IP^-1 -> Output
;                               |
;                               --->   64 bit -> 32 bit <EDX:EAX> 

                
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

; rn can get that 64 bit and scrambled | here we are at scramble IP next do 16 rounds of Feistel then scramble back
; but the split in the Feistel is already done

; Feistel flow: split -> cipher function: expansion, subkey, s-box, permutaion -> cross xor -> swap

; Feistel whatever 16 round start here:
        IP_Scramble_Done:









        pop edi
        pop esi
        pop ecx
        pop ebx

        pop ebp
        ret 8

ProcessDES ENDP

OPTION PROLOGUE:PrologueDef
OPTION EPILOGUE:EpilogueDef