#ifndef __S_WINDOW_H__
#define __S_WINDOW_H__

#include <stdio.h>
#include "SA.h"

#define ReplayWindowSize 32
int checkSeq_num(SA* current_sa, unsigned long seq);
int initiateWindow(s_window s);
void printfWindow(s_window s);

#endif
