/* Delta.h -- Delta converter
2023-03-03 : Igor Pavlov : Public domain */

#ifndef OPENZIP_INC_DELTA_H
#define OPENZIP_INC_DELTA_H

#include "OzTypes.h"

EXTERN_C_BEGIN

#define DELTA_STATE_SIZE 256

void Delta_Init(Byte *state);
void Delta_Encode(Byte *state, unsigned delta, Byte *data, SizeT size);
void Delta_Decode(Byte *state, unsigned delta, Byte *data, SizeT size);

EXTERN_C_END

#endif
