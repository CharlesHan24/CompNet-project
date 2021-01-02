#ifndef _HOST_H
#define _HOST_H

#include "header.h"

class defense_host_t{
public:
	defense_host_t ();

	defense_host_t (uint32_t pid);

	void switch_namespace(uint32_t pid);

	int attachToNS(char* path);
};

#endif
