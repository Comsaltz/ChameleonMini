/*
 * NFCCommand.c
 *
 *  Created on: 20.03.2013
 *      Author: skuser
 */

#include <stdio.h>
#include "NFC_Command.h"
#include "ISO14443-3A.h"
#include "../Codec/ISO14443-2A.h"
#include "../Memory.h"
#include "../Random.h"
#include "CryptoTDEA.h"
#include "../Terminal/Terminal.h"
#include "../Terminal/CommandLine.h"


#define ATQA_VALUE              0x0044
#define SAK_CL1_VALUE           ISO14443A_SAK_INCOMPLETE
#define SAK_CL2_VALUE           ISO14443A_SAK_COMPLETE_NOT_COMPLIANT

#define ACK_VALUE               0x0A
#define ACK_FRAME_SIZE          4 /* Bits */
#define NAK_INVALID_ARG         0x00
#define NAK_CRC_ERROR           0x01
#define NAK_CTR_ERROR           0x04
#define NAK_EEPROM_ERROR        0x05
#define NAK_OTHER_ERROR         0x06
/* NOTE: the spec is not crystal clear which error is returned */
#define NAK_AUTH_REQUIRED       NAK_OTHER_ERROR
#define NAK_AUTH_FAILED         NAK_OTHER_ERROR
#define NAK_FRAME_SIZE          4

/* ISO commands */
#define CMD_HALT                0x50
/* ULC commands */
#define CMD_ULC_AUTH             0x1A
#define CMD_ULC_AUTH_2            0xAF
#define CMD_ULC_AUTH_FINISHED    0x00
/* EV0 commands */
#define CMD_READ                0x30
#define CMD_READ_FRAME_SIZE     2 /* without CRC bytes */
#define CMD_WRITE               0xA2
#define CMD_WRITE_FRAME_SIZE    6 /* without CRC bytes */
#define CMD_COMPAT_WRITE        0xA0
#define CMD_COMPAT_WRITE_FRAME_SIZE 2


/* Tag memory layout; addresses and sizes in bytes */
#define NFC_CMD_COUNTER_ADDRESS    0x29
#define MF_ULC_READ_MAX_PAGE 0x2C

#define UID_CL1_ADDRESS         0x00
#define UID_CL1_SIZE            3
#define UID_BCC1_ADDRESS        0x03
#define UID_CL2_ADDRESS         0x04
#define UID_CL2_SIZE            4
#define UID_BCC2_ADDRESS        0x08
#define LOCK_BYTES_1_ADDRESS    0x0A
#define LOCK_BYTES_2_ADDRESS    0x90
#define CONFIG_AREA_SIZE        0x10
#define CONF_AUTH0_OFFSET       0x03
#define CONF_ACCESS_OFFSET      0x04
#define CONF_VCTID_OFFSET       0x05
#define CONF_PASSWORD_OFFSET    0x08
#define CONF_PACK_OFFSET        0x0C

#define CONF_ACCESS_PROT        0x80
#define CONF_ACCESS_CNFLCK      0x40

#define CNT_MAX                 2
#define CNT_SIZE                4
#define CNT_MAX_VALUE           0x00FFFFFF

#define BYTES_PER_READ          4 //16
#define PAGE_READ_MIN           0x00

#define BYTES_PER_WRITE         4
#define PAGE_WRITE_MIN          0x02

#define BYTES_PER_COMPAT_WRITE  16

#define VERSION_INFO_LENGTH     8
#define SIGNATURE_LENGTH        32

uint8_t t = 0;

static enum {
    UL_EV0,
    UL_C,
    UL_EV1,
} Flavor;

static enum {
    STATE_HALT,
    STATE_IDLE,
    STATE_READY1,
    STATE_READY2,
    STATE_ACTIVE,
    STATE_COMPAT_WRITE,
    STATE_AUTH
} State;

static bool FromHalt = false;
static uint8_t PageCount;
static bool ArmedForCompatWrite;
static uint8_t CompatWritePageAddress;
static bool Authenticated;
static uint8_t FirstAuthenticatedPage;
static bool ReadAccessProtected;
static uint8_t InitialVector[8] = {0};
static uint8_t TripleDesKey [16];

static void AppInitCommon(void) {
    State = STATE_IDLE;
    FromHalt = false;
    Authenticated = false;
    ArmedForCompatWrite = false;
}

void NFCCommandAppInit(void) {
    /* Set up the emulation flavor */
    Flavor = UL_EV0;
    /* EV0 cards have fixed size */
    PageCount = NFC_COMMAND_PAGES;
    /* Default values */
    FirstAuthenticatedPage = 0xFF;
    ReadAccessProtected = false;
    AppInitCommon();
}

void NFCCommandAppReset(void) {
    State = STATE_IDLE;
}

void NFCCommandAppTask(void) {

}

static bool VerifyAuthentication(uint8_t PageAddress) {
    /* No authentication for EV0 cards; always pass */
    if (Flavor < UL_C) {
        return true;
    }
    /* If authenticated, no verification needed */
    if (Authenticated) {
        return true;
    }
    /* Otherwise, verify the accessed page is below the limit */
    return PageAddress < FirstAuthenticatedPage;
}

static bool IncrementCounter(uint8_t *IncrementValue) {
    uint16_t CounterValue;
    MemoryReadBlock(&CounterValue, NFC_CMD_COUNTER_ADDRESS, 2);
    if (CounterValue == 0) {
        CounterValue = IncrementValue[0] + (IncrementValue[1] << 8);
        MemoryWriteBlock(&CounterValue, NFC_CMD_COUNTER_ADDRESS, 2);
        return true;
    } else {
        IncrementValue[0] &= 0x0f;
        if (IncrementValue[0] <= (0xffff - CounterValue)) {
            CounterValue += IncrementValue[0];
            MemoryWriteBlock(&CounterValue, NFC_CMD_COUNTER_ADDRESS, 2);
            return true;
        }
        return false;
    }
}

/* Perform access verification and commit data if passed */
static uint8_t NFCWritePage(uint8_t PageAddress, uint8_t * const Buffer) {
    if (!ActiveConfiguration.ReadOnly) {
        MemoryWriteBlock(Buffer, PageAddress * NFC_COMMAND_PAGE_SIZE, NFC_COMMAND_PAGE_SIZE);
    } else {
        /* If the chameleon is in read only mode, it silently
         * ignores any attempt to write data. */
    }
    return 0;
}

/*
 --------------------------------------------------
 * All Above copied from ultralight so chameleon emulates ultralight
 * ----------------------------------------------
 */

/* Handles processing of MF commands */
static uint16_t AppProcess(uint8_t * const Buffer, uint16_t ByteCount) {
    uint8_t Cmd = Buffer[0];

    /* Handle the compatibility write command */
    if (ArmedForCompatWrite) {
        ArmedForCompatWrite = false;

        //Handle MF ULC counter
        if (CompatWritePageAddress == NFC_CMD_COUNTER_ADDRESS && Flavor == UL_C) {
            if (IncrementCounter(&Buffer[2])) {
                Buffer[0] = ACK_VALUE;
                return ACK_FRAME_SIZE;
            } else {
                Buffer[0] = NAK_INVALID_ARG;
                return NAK_FRAME_SIZE;
            }
        }
        NFCWritePage(CompatWritePageAddress, &Buffer[2]);
        Buffer[0] = ACK_VALUE;
        return ACK_FRAME_SIZE;
    }

    /* Handle EV0 commands */
    switch (Cmd) {

        case CMD_READ:
        {

            uint8_t PageAddress = Buffer[1];
            uint8_t PageLimit;
            uint8_t Offset;
            /* For EV1+ cards, ensure the wraparound is at the first protected page */
            if (Flavor >= UL_C && ReadAccessProtected && !Authenticated) {
                PageLimit = FirstAuthenticatedPage;
            } else {
                if (Flavor == UL_C) PageLimit = MF_ULC_READ_MAX_PAGE; // For ULC make sure wraparound is at the first key page
                else PageLimit = PageCount;
            }
            /* Validation */
            if (PageAddress >= PageLimit) {
                Buffer[0] = NAK_INVALID_ARG;
                return NAK_FRAME_SIZE;
            }
            /* Read out, emulating the wraparound */
            for (Offset = 0; Offset < 4; Offset += 4) { //BYTES_PER_READ   Offset += 4
                MemoryReadBlock(&Buffer[Offset], PageAddress * NFC_COMMAND_PAGE_SIZE, NFC_COMMAND_PAGE_SIZE);
                PageAddress++;
                if (PageAddress == PageLimit) {
                    PageAddress = 0;
                }
            }
            ISO14443AAppendCRCA(Buffer, BYTES_PER_READ);
            return (BYTES_PER_READ + ISO14443A_CRCA_SIZE) * 8;
        }

        case CMD_WRITE:
        {
            /* This is a write command containing 4 bytes of data that
             * should be written to the given page address. */
            uint8_t PageAddress = Buffer[1];

            //Handle MF ULC counter
            if (PageAddress == NFC_CMD_COUNTER_ADDRESS && Flavor == UL_C) {
                if (IncrementCounter(&Buffer[2])) {
                    Buffer[0] = ACK_VALUE;
                    return ACK_FRAME_SIZE;
                } else {
                    Buffer[0] = NAK_INVALID_ARG;
                    return NAK_FRAME_SIZE;
                }
            }

            /* Validation */
            if ((PageAddress < PAGE_WRITE_MIN) || (PageAddress >= PageCount)) {
                Buffer[0] = NAK_INVALID_ARG;
                return NAK_FRAME_SIZE;
            }
            if (!VerifyAuthentication(PageAddress)) {
                Buffer[0] = NAK_AUTH_REQUIRED;
                return NAK_FRAME_SIZE;
            }
            ///Handles NFC Commands
            for (uint8_t i = 2; i < 6; i++) {
                uint8_t byte = Buffer[i];
                if (byte == '\n') { //catches line feed as termination character and converts to carriage return
                    byte = '\r';
                    TerminalSendString("\n\r");
                }
                if (byte == 6) { // if Acknowledgment received
                    NFCAnswer(NFCResponse); //send command response
                }
                CommandLineProcessByte(byte); //process the byte and trigger command on termination character
                TerminalSendChar(byte);
            }

            Buffer[0] = ACK_VALUE;
            return ACK_FRAME_SIZE;
        }

        case CMD_COMPAT_WRITE:
        {
            uint8_t PageAddress = Buffer[1];
            /* Validation */
            if ((PageAddress < PAGE_WRITE_MIN) || (PageAddress >= PageCount)) {
                Buffer[0] = NAK_INVALID_ARG;
                return NAK_FRAME_SIZE;
            }
            if (!VerifyAuthentication(PageAddress)) {
                Buffer[0] = NAK_AUTH_REQUIRED;
                return NAK_FRAME_SIZE;
            }
            /* CRC check passed and page-address is within bounds.
             * Store address and proceed to receiving the data. */
            CompatWritePageAddress = PageAddress;
            ArmedForCompatWrite = true;
            Buffer[0] = ACK_VALUE;
            return ACK_FRAME_SIZE;
        }

        case CMD_HALT:
        {
            /* Halts the tag. According to the ISO14443, the second
             * byte is supposed to be 0. */
            if (Buffer[1] == 0) {
                /* According to ISO14443, we must not send anything
                 * in order to acknowledge the HALT command. */
                State = STATE_HALT;
                return ISO14443A_APP_NO_RESPONSE;
            } else {
                Buffer[0] = NAK_INVALID_ARG;
                return NAK_FRAME_SIZE;
            }
        }
        default:
            break;
    }

    // Command not handled. Switch to idle. 
    State = STATE_IDLE;
    return ISO14443A_APP_NO_RESPONSE;
}

uint16_t NFCCommandAppProcess(uint8_t *Buffer, uint16_t BitCount) {
    uint8_t Cmd = Buffer[0];
    uint16_t ByteCount;

    switch (State) {
        case STATE_IDLE:
        case STATE_HALT:
            FromHalt = State == STATE_HALT;
            if (ISO14443AWakeUp(Buffer, &BitCount, ATQA_VALUE, FromHalt)) {
                // We received a REQA or WUPA command, so wake up. 
                State = STATE_READY1;
                return BitCount;
            }
            break;

        case STATE_READY1:
            if (ISO14443AWakeUp(Buffer, &BitCount, ATQA_VALUE, FromHalt)) {
                State = FromHalt ? STATE_HALT : STATE_IDLE;
                return ISO14443A_APP_NO_RESPONSE;
            } else if (Cmd == ISO14443A_CMD_SELECT_CL1) {
                /* Load UID CL1 and perform anticollision. Since
                 * MF Ultralight use a double-sized UID, the first byte
                 * of CL1 has to be the cascade-tag byte. */
                uint8_t UidCL1[ISO14443A_CL_UID_SIZE] = {[0] = ISO14443A_UID0_CT};

                MemoryReadBlock(&UidCL1[1], UID_CL1_ADDRESS, UID_CL1_SIZE);

                if (ISO14443ASelect(Buffer, &BitCount, UidCL1, SAK_CL1_VALUE)) {
                    /* CL1 stage has ended successfully */
                    State = STATE_READY2;
                }

                return BitCount;
            } else {
                /* Unknown command. Enter halt state */
                State = STATE_IDLE;
            }
            break;

        case STATE_READY2:
            if (ISO14443AWakeUp(Buffer, &BitCount, ATQA_VALUE, FromHalt)) {
                State = FromHalt ? STATE_HALT : STATE_IDLE;
                return ISO14443A_APP_NO_RESPONSE;
            } else if (Cmd == ISO14443A_CMD_SELECT_CL2) {
                /* Load UID CL2 and perform anticollision */
                uint8_t UidCL2[ISO14443A_CL_UID_SIZE];

                MemoryReadBlock(UidCL2, UID_CL2_ADDRESS, UID_CL2_SIZE);

                if (ISO14443ASelect(Buffer, &BitCount, UidCL2, SAK_CL2_VALUE)) {
                    /* CL2 stage has ended successfully. This means
                     * our complete UID has been sent to the reader. */
                    State = STATE_ACTIVE;
                }

                return BitCount;
            } else {
                /* Unknown command. Enter halt state */
                State = STATE_IDLE;
            }
            break;

        case STATE_ACTIVE:
            /* Preserve incoming data length */
            ByteCount = (BitCount + 7) >> 3;
            if (ISO14443AWakeUp(Buffer, &BitCount, ATQA_VALUE, FromHalt)) {
                State = FromHalt ? STATE_HALT : STATE_IDLE;
                return ISO14443A_APP_NO_RESPONSE;
            }
            /* At the very least, there should be 3 bytes in the buffer. */
            if (ByteCount < (1 + ISO14443A_CRCA_SIZE)) {
                State = STATE_IDLE;
                return ISO14443A_APP_NO_RESPONSE;
            }
            /* All commands here have CRCA appended; verify it right away */
            ByteCount -= 2;
            if (!ISO14443ACheckCRCA(Buffer, ByteCount)) {
                Buffer[0] = NAK_CRC_ERROR;
                return NAK_FRAME_SIZE;
            }
            return AppProcess(Buffer, ByteCount);

        case STATE_AUTH: // ULC Authing
            ByteCount = (BitCount + 7) >> 3;
            /* We check if we received an auth message */
            if (Buffer[0] == CMD_ULC_AUTH_2 && ISO14443ACheckCRCA(Buffer, ByteCount - 2)) {
                uint8_t tmpBuff [8];
                uint8_t RNDA [8] = {0};
                CryptoDecrypt2KTDEA_CBCReceive(1, &Buffer[1], RNDA, InitialVector, TripleDesKey);

                CryptoDecrypt2KTDEA_CBCReceive(1, &Buffer[9], tmpBuff, InitialVector, TripleDesKey);

            }

            State = STATE_IDLE;
            Buffer[0] = NAK_AUTH_FAILED;
            return NAK_FRAME_SIZE;

        default:
            /* Unknown state? Should never happen. */
            break;
    }

    /* No response has been sent, when we reach here */
    return ISO14443A_APP_NO_RESPONSE;
}
//---- Writes the Status ID and message to pages -----
void NFCStatusId(const char *s) {
    uint8_t Status[48];
    uint8_t i = 0, k = 0;
    char c;

    while ((c = pgm_read_byte(s++)) != '\0') {
        Status[i] = c;
        i++;
    }
    Status[i] = '\n';
    i++;
    for (i = i; i < 48; i++) {
        Status[i] = 0;
    }
    for (uint8_t j = 4; j < 16; j++) {
        NFCWritePage(j, &Status[k]);
        k += 4;
    }
}

//---- Writes command response
void NFCAnswer(const char *s) {

    uint8_t k = 0, i;

    const char *message;

    if (NFCResponse[0] != '\0') {
        message = s;
        float len = strlen(message); //length of message
        uint8_t m = ceil(len / 48); // number of writes needed
        uint16_t n = m * 48; //number of bytes that will be sent
        uint8_t Status[n];


        for (i = 0; i < len; i++) {
            Status[i] = *message; //converts message to int array
            message++;
        }
        for (i = i + 1; i < n; i++) {
            Status[i] = '\0'; //pads with null characters
        }

        uint8_t tmpBuffer[48];
        uint8_t q = t * 48; //number of characters into message that have been written
        for (uint8_t i = 0; i < 48; i++) {
            tmpBuffer[i] = Status[q + i];
        }

        for (uint8_t j = 4; j < 16; j++) {
            NFCWritePage(j, &tmpBuffer[k]); //write message
            k += 4;
        }
        if (tmpBuffer[47] != '\0') {
            t++;
        } else {
            t = 0;
        }
    }
}
