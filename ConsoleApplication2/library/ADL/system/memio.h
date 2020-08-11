#ifndef _MEMIO_H
#define _MEMIO_H

#define TEMP(n) TEMP ## n 

#define MEMCOPY(Destination, Source, Size) \
do \
{ \
	int LINE = __LINE__; \
	int TEMP(LINE) = 0; \
	for(; TEMP(LINE) != Size; TEMP(LINE)++) \
	{ \
		((unsigned char *)Destination)[TEMP(LINE)] = ((unsigned char *)Source)[TEMP(LINE)]; \
	} \
} while(0);


#define MEMSET(Destination, Source, Size) \
do \
{ \
	int LINE = __LINE__; \
	int TEMP(LINE) = 0; \
	for(; TEMP(LINE) != Size; TEMP(LINE)++) \
	{ \
		((unsigned char *)Destination)[TEMP(LINE)] = Source; \
	} \
} while(0);

#endif