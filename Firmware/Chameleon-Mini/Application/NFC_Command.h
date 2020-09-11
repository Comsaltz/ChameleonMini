/*
 * MifareUltralight.h
 *
 *  Created on: 20.03.2013
 *      Author: skuser
 */

#ifndef NFC_Command_H_
#define NFC_Command_H_

#include "Application.h"
#include "ISO14443-3A.h"


#define MIFARE_ULTRALIGHT_UID_SIZE    ISO14443A_UID_SIZE_DOUBLE
#define NFC_COMMAND_PAGE_SIZE   4
#define NFC_COMMAND_PAGES       16
#define NFC_COMMAND_MEM_SIZE          (NFC_COMMAND_PAGES * NFC_COMMAND_PAGE_SIZE)

void NFCCommandAppInit(void);
void NFCCommandAppReset(void);
void NFCCommandAppTask(void);

uint16_t NFCCommandAppProcess(uint8_t *Buffer, uint16_t BitCount);

void NFCStatusId(const char *s);
void NFCAnswer(const char *s);
void PageRead(void);

#endif /* MIFAREULTRALIGHT_H_ */
