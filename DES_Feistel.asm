TITLE Module C: DES 16-Round Feistel Core Engine

; ==============================================================================
; Description: 
; Program for processing the Data Encryption Standard algorithm 
; Includes the 16-Round Feistel Network, PKCS#7 Padding mechanism, and ECB mode.
; ==============================================================================

.386
;.model flat, stdcall
INCLUDE C:\Irvine\Irvine32.inc

ProcessDES PROTO :PTR BYTE, :PTR BYTE

PUBLIC EncryptBuffer
PUBLIC DecryptBuffer
 
BlockSize       EQU 8
KeyScheduleSize EQU 96
SubkeyLen       EQU 6
NumRounds       EQU 16

.data
; Initial Permutation (IP) - Permutes data bits before entering the 16-round Feistel.
IPTable  BYTE 58, 50, 42, 34, 26, 18, 10, 2
         BYTE 60, 52, 44, 36, 28, 20, 12, 4
         BYTE 62, 54, 46, 38, 30, 22, 14, 6
         BYTE 64, 56, 48, 40, 32, 24, 16, 8
         BYTE 57, 49, 41, 33, 25, 17,  9, 1
         BYTE 59, 51, 43, 35, 27, 19, 11, 3
         BYTE 61, 53, 45, 37, 29, 21, 13, 5
         BYTE 63, 55, 47, 39, 31, 23, 15, 7

; Inverse Initial Permutation (IP^-1) - Reverses the bit permutation after the 16 rounds.
IPInvTable  BYTE 40,  8, 48, 16, 56, 24, 64, 32
            BYTE 39,  7, 47, 15, 55, 23, 63, 31
            BYTE 38,  6, 46, 14, 54, 22, 62, 30
            BYTE 37,  5, 45, 13, 53, 21, 61, 29
            BYTE 36,  4, 44, 12, 52, 20, 60, 28
            BYTE 35,  3, 43, 11, 51, 19, 59, 27
            BYTE 34,  2, 42, 10, 50, 18, 58, 26
            BYTE 33,  1, 41,  9, 49, 17, 57, 25
    
; Expansion Table (E-Box) - Expands the 32-bit right half to 48 bits.
ETable  BYTE 32,  1,  2,  3,  4,  5
        BYTE  4,  5,  6,  7,  8,  9
        BYTE  8,  9, 10, 11, 12, 13
        BYTE 12, 13, 14, 15, 16, 17
        BYTE 16, 17, 18, 19, 20, 21
        BYTE 20, 21, 22, 23, 24, 25
        BYTE 24, 25, 26, 27, 28, 29
        BYTE 28, 29, 30, 31, 32,  1

; Permutation Table (P-Box) - Permutes the 32-bit output from the S-Boxes.
PTable  BYTE 16,  7, 20, 21
        BYTE 29, 12, 28, 17
        BYTE  1, 15, 23, 26
        BYTE  5, 18, 31, 10
        BYTE  2,  8, 24, 14
        BYTE 32, 27,  3,  9
        BYTE 19, 13, 30,  6
        BYTE 22, 11,  4, 25

; S-Boxes 1 to 8 - compressing 48 bits back to 32 bits.
SBox1   BYTE 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7
        BYTE 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8
        BYTE 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0
        BYTE 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
SBox2   BYTE 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10
        BYTE 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5
        BYTE 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15
        BYTE 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
SBox3   BYTE 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8
        BYTE 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1
        BYTE 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7
        BYTE 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
SBox4   BYTE 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15
        BYTE 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9
        BYTE 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4
        BYTE 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
SBox5   BYTE 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9
        BYTE 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6
        BYTE 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14
        BYTE 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
SBox6   BYTE 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11
        BYTE 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8
        BYTE 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6
        BYTE 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
SBox7   BYTE 4, 11, 2, 14, 15, 0, 8, 13, 3, 7, 9, 5, 6, 10, 12, 1
        BYTE 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6
        BYTE 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2
        BYTE 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
SBox8   BYTE 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7
        BYTE 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2
        BYTE 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8
        BYTE 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 

.code

OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

; ==============================================================================
; ProcessDES
; Receives: 
;   pDataBlock   - Pointer to an 8-byte data block.
;   pKeySchedule - Pointer to the 16-round subkeys (96 bytes).
; Returns: 
;   Overwrites the processed data back into the original pDataBlock memory.
; ==============================================================================
ProcessDES PROC pDataBlock:PTR BYTE, pKeySchedule:PTR BYTE

; 1. Stack Frame Setup
        push ebp
        mov ebp, esp

        ; Protect critical registers before use
        push ebx        ; Used as a loop counter
        push ecx        ; Stores the Left Half
        push esi        ; Used as a memory pointer
        push edi        ; Stores the Right Half

; 2. Initial Permutation (IP) 
; Extract 64 bits from pDataBlock, permute, and split into Left (ECX) and Right (EDI).
        mov esi, [ebp + 8]
        xor ebx, ebx

        xor ecx, ecx
        xor edi, edi

IPScramble:
        cmp ebx, 64
        jae IPScrambleDone

        xor eax, eax
        movzx eax, BYTE PTR IPTable[ebx]
        sub eax, 1

        push ecx
        xor edx, edx
        mov ecx, 8
        div ecx
        movzx eax, BYTE PTR [esi + eax]
        mov ecx, 7
        sub ecx, edx
        shr eax, cl     
        and eax, 1
        pop ecx

        cmp ebx, 32
        jb PackLeft 
        
        ; Insert bit into the right half (EDI)
        shl edi, 1      
        or edi, eax     
        jmp PackDone

PackLeft:
        ; Insert bit into the left half (ECX)
        shl ecx, 1      
        or ecx, eax     

PackDone:
        inc ebx
        jmp IPScramble

IPScrambleDone:
; 3. The 16-Round Feistel Network
        xor ebx, ebx    ; Clear EBX to use as the 16-round counter
        xor eax, eax    
        xor edx, edx     

FeistelRound:
        cmp ebx, 16
        jae FeistelDone

        push ebx        ; Save the round counter to the Stack
        push ecx        ; Save L(i-1) to the Stack for later Cross-XOR

        xor ebx, ebx
        xor eax, eax    ; EAX = Expanded lower 32
        xor edx, edx    ; EDX = Expanded upper 16
        
; --- Step A: Expansion (E) ---
; Expand the 32-bit right half (EDI) into 48 bits (EAX:EDX)
ExpansionLoop:
        cmp ebx, 48
        jae ExpansionDone

        xor ecx, ecx
        movzx ecx, BYTE PTR ETable[ebx]
        sub ecx, 1

        mov esi, 31
        sub esi, ecx
        mov ecx, esi

        mov esi, edi    
        shr esi, cl     
        and esi, 1

        shl eax, 1      
        rcl edx, 1      
        
        or eax, esi

        inc ebx
        jmp ExpansionLoop

ExpansionDone:
        mov ebx, DWORD PTR [esp+4] ; Retrieve the current round number to calculate the key address

; --- Step B: Subkey XOR ---
; XOR the 48-bit expanded data with the current round's subkey
        lea esi, [ebx + ebx*2]  
        add esi, esi            
        add esi, [ebp + 12]     
        
        push ebx
        mov  ebx, DWORD PTR [esi+2]   
        bswap ebx
        xor  eax, ebx

        mov  bx, WORD PTR [esi]       
        xchg bh, bl
        xor  dx, bx
        pop  ebx

; --- Step C: S-Box Substitution ---
; Split the 48-bit data into eight 6-bit blocks and pass them through S-Boxes to compress into 32 bits
        push ebx 
        push ecx 
        push edi    
        
        xor edi, edi
        
; S-Box 1
        movzx ecx, dx   
        shr ecx, 10
        and ecx, 3Fh    ; Mask to extract only 6 bits

        ; Calculate Row (bits 1 and 6)
        mov esi, ecx
        shr esi, 4
        and esi, 2
        mov ebx, ecx
        and ebx, 1 
        or esi, ebx 

        ; Calculate Column (bits 2-5)
        mov ebx, ecx
        shr ebx, 1 
        and ebx, 0Fh 

        ; Retrieve the 4-bit value from the S-Box 1 table
        shl esi, 4
        add esi, ebx    
        movzx ebx, BYTE PTR SBox1[esi]        
        
        shl ebx, 28     ; Shift to assemble into the 32-bit register
        or edi, ebx

; S-Box 2
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
        movzx ebx, BYTE PTR SBox2[esi]   
        shl ebx, 24
        or edi, ebx

; S-Box 3
        movzx ecx, dx
        and ecx, 0Fh 
        shl ecx, 2      
        mov esi, eax
        shr esi, 30 
        or ecx, esi 
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
        movzx ebx, BYTE PTR SBox3[esi]
        shl ebx, 20 
        or edi, ebx

; S-Box 4
        mov ecx, eax
        shr ecx, 24     
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
        movzx ebx, BYTE PTR SBox4[esi]
        shl ebx, 16 
        or edi, ebx

; S-Box 5
        mov ecx, eax
        shr ecx, 18     
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
        movzx ebx, BYTE PTR SBox5[esi]
        shl ebx, 12
        or edi, ebx

; S-Box 6
        mov ecx, eax
        shr ecx, 12     
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
        movzx ebx, BYTE PTR SBox6[esi]
        shl ebx, 8
        or edi, ebx

; S-Box 7
        mov ecx, eax
        shr ecx, 6     
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
        movzx ebx, BYTE PTR SBox7[esi]
        shl ebx, 4      
        or edi, ebx

; S-Box 8
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
        movzx ebx, BYTE PTR SBox8[esi]
        or edi, ebx

; --- Step D: Permutation (P) ---
; Permute the bits of the 32-bit S-Box output
        mov eax, edi
        pop edi
        pop ecx
        pop ebx

        push ebx
        xor ebx, ebx 
        xor edx, edx

PermutationLoop:
        cmp ebx, 32 
        jae PermutationDone

        push ecx 
        xor ecx, ecx
        movzx ecx, BYTE PTR PTable[ebx]
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
        jmp PermutationLoop

PermutationDone:
        pop ebx

        pop ecx             ; Retrieve Old Left (L) to prepare for XOR
        pop ebx             ; Retrieve the round counter

; --- Step E: Cross-XOR & Swap ---
; R_new = L_old XOR f(R_old, K)
        xor ecx, edx
        xchg ecx, edi       ; Swap Left and Right for the next round

        inc ebx
        jmp FeistelRound

FeistelDone:
; 4. Final Swap & Inverse Initial Permutation (IP^-1)
; Permute the final 64-bit data (after the preoutput swap) back using the IP_Inv_Table
        mov esi, [ebp + 8] 
        push esi

        xor esi, esi       
        xor edx, edx        
        
        push ebx
        xor ebx, ebx   

IPInvLoop:
        cmp ebx, 64
        jae IPInvDone

        xor eax, eax
        movzx eax, BYTE PTR IPInvTable[ebx]
        sub eax, 1

        cmp eax, 32
        jb ExtractEDI
        
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
        jmp AppendBit

ExtractEDI:
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

AppendBit: 
        cmp ebx, 32 
        jb PackEDX 
        shl esi, 1 
        or esi, eax 
        jmp LoopEnd 
PackEDX: 
        shl edx, 1 
        or edx, eax 
LoopEnd: 
        inc ebx 
        jmp IPInvLoop

IPInvDone: 
        pop ebx 
        pop eax

        ; Save the final 64-bit result back into memory, overwriting the original block
        bswap edx 
        mov [eax], edx
        bswap esi
        mov [eax + 4], esi

; 5. Stack Epilogue
; Restore critical registers before exiting the function
        pop edi
        pop esi
        pop ecx
        pop ebx

        pop ebp
        ret 8
ProcessDES ENDP

OPTION PROLOGUE:PrologueDef
OPTION EPILOGUE:EpilogueDef

; ==============================================================================
; EncryptBuffer
; Receives: 
;   pInput       - Pointer to raw data
;   inputSize    - Size of data (bytes)
;   pOutput      - Pointer to store Ciphertext
;   pOutputSize  - Pointer to store output size
;   pSubkeys     - 16-round key schedule
; Note: The USES operator automatically generates PUSH and POP instructions for the specified registers[cite: 10, 11].
; ==============================================================================
EncryptBuffer PROC USES ebx ecx edx esi edi \
    pInput:PTR BYTE, inputSize:DWORD, pOutput:PTR BYTE, pOutputSize:PTR DWORD, pSubkeys:PTR BYTE
    
    ; Declare LOCAL variables, which are allocated on the Stack and released when the subroutine ends[cite: 11].
    LOCAL padLen:DWORD
    LOCAL totalSize:DWORD
    
    ; Copy original data to the Output Buffer
    mov     esi, pInput
    mov     edi, pOutput
    mov     ecx, inputSize
EBCopyLoop:
    cmp     ecx, 0
    je      EBCopyDone
    mov     al, BYTE PTR [esi]
    mov     BYTE PTR [edi], al
    inc     esi
    inc     edi
    dec     ecx
    jmp     EBCopyLoop
EBCopyDone:

    ; Calculate PKCS#7 Padding: find the remainder and bytes needed to reach a multiple of 8
    mov     eax, inputSize
    xor     edx, edx
    mov     ecx, BlockSize
    div     ecx
    mov     eax, BlockSize
    sub     eax, edx
    mov     padLen, eax
 
    mov     eax, inputSize
    add     eax, padLen
    mov     totalSize, eax
 
    ; Append Padding bytes to the end of the last block
    mov     al, BYTE PTR padLen
    mov     ecx, padLen
EBPadLoop:
    cmp     ecx, 0
    je      EBPadDone
    mov     BYTE PTR [edi], al
    inc     edi
    dec     ecx
    jmp     EBPadLoop
EBPadDone:

    ; Process ECB encryption by looping and calling ProcessDES every 8 bytes
    mov     esi, pOutput
    mov     ecx, totalSize
    shr     ecx, 3
EBBlockLoop:
    cmp     ecx, 0
    je      EBBlockDone
    invoke  ProcessDES, esi, pSubkeys
    add     esi, BlockSize
    dec     ecx
    jmp     EBBlockLoop
EBBlockDone:
 
    mov     eax, pOutputSize
    mov     edx, totalSize
    mov     DWORD PTR [eax], edx
 
    xor     eax, eax
    ret
EncryptBuffer ENDP

; ==============================================================================
; DecryptBuffer
; Receives the same parameters as EncryptBuffer. 
; Reverses the key schedule (K16 -> K1) and decrypts in ECB mode, then removes Padding.
; ==============================================================================
DecryptBuffer PROC USES ebx ecx edx esi edi \
    pInput:PTR BYTE, inputSize:DWORD, pOutput:PTR BYTE, pOutputSize:PTR DWORD, pSubkeys:PTR BYTE
    
    LOCAL reversedKeys[KeyScheduleSize]:BYTE
    LOCAL padLen:DWORD
 
    ; Check if the encrypted file size is perfectly divisible by 8
    mov     eax, inputSize
    cmp     eax, 0
    je      DBFailed
    xor     edx, edx
    mov     ecx, BlockSize
    div     ecx
    cmp     edx, 0
    jne     DBFailed
 
    ; Copy the Subkey schedule but in reverse order for decryption
    mov     ecx, 0
DBReverseLoop:
    cmp     ecx, NumRounds
    jae     DBReverseDone
 
    mov     eax, ecx
    imul    eax, SubkeyLen
    mov     esi, pSubkeys
    add     esi, eax                
 
    mov     eax, NumRounds - 1
    sub     eax, ecx
    imul    eax, SubkeyLen
    lea     edi, reversedKeys
    add     edi, eax                
 
    mov     ebx, 0
DBCopyKeyByte:
    cmp     ebx, SubkeyLen
    jae     DBCopyKeyByteDone
    mov     dl, BYTE PTR [esi+ebx]
    mov     BYTE PTR [edi+ebx], dl
    inc     ebx
    jmp     DBCopyKeyByte
DBCopyKeyByteDone:
 
    inc     ecx
    jmp     DBReverseLoop
DBReverseDone:

    ; Copy Ciphertext to the Output Buffer
    mov     esi, pInput
    mov     edi, pOutput
    mov     ecx, inputSize
DBCopyLoop:
    cmp     ecx, 0
    je      DBCopyDone
    mov     al, BYTE PTR [esi]
    mov     BYTE PTR [edi], al
    inc     esi
    inc     edi
    dec     ecx
    jmp     DBCopyLoop
DBCopyDone:

    ; Process ECB decryption using the reversed keys
    mov     esi, pOutput
    mov     ecx, inputSize
    shr     ecx, 3
DBBlockLoop:
    cmp     ecx, 0
    je      DBBlockDone
    lea     eax, reversedKeys
    invoke  ProcessDES, esi, eax
    add     esi, BlockSize
    dec     ecx
    jmp     DBBlockLoop
DBBlockDone:

    ; Read the last byte of the file to determine the PKCS#7 Padding size
    mov     esi, pOutput
    add     esi, inputSize
    dec     esi
    movzx   eax, BYTE PTR [esi]
    mov     padLen, eax
 
    ; Validate Padding (must be between 1 and 8)
    cmp     eax, 1
    jb      DBFailed
    cmp     eax, BlockSize
    ja      DBFailed
    cmp     eax, inputSize
    ja      DBFailed
 
    ; Calculate the actual file size (Total Size - Padding Size)
    mov     eax, pOutputSize
    mov     edx, inputSize
    sub     edx, padLen
    mov     DWORD PTR [eax], edx
 
    xor     eax, eax
    ret
 
DBFailed:
    mov     eax, 1
    ret
DecryptBuffer ENDP

END
