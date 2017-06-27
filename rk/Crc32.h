#ifndef __CRC32_H__
#define __CRC32_H__

void crc32Init(unsigned int *pCrc32);
void crc32Update(unsigned int *pCrc32, const char *pData, unsigned int uSize);
void crc32Finish(unsigned int *pCrc32);
unsigned long MyCrc32(unsigned long crc, char *buff, int len);

#endif