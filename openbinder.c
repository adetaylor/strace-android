/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 2007 Adrian Taylor <ade@hohum.me.uk>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *	$Id: time.c,v 1.19 2007/01/13 11:17:38 ldv Exp $
 */

#include "defs.h"
#include <inttypes.h>
#include <linux/types.h>

#define LINUX

#ifdef LINUX
#include <linux/version.h>
#include <linux/ioctl.h>
#include "binder.h"
#endif /* LINUX */

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>


typedef unsigned int u32;

static int logfh=0;
static int logfhopened = 0;

void logmsg(str)
char* str;
{
	if (!logfhopened)
	{
		logfh = open("/dev/kmsg",O_WRONLY|O_CREAT,0666);
		logfhopened = 1;
	}
	if (logfh)
	{
		write(logfh,str,strlen(str));
	}
}


void dump_bytes(data, size)
char* data;
unsigned long size;
{
	int i;
	tprintf("[");
	for (i=0;i<size;i++) {
		tprintf("0x%02x", (u32)data[i]);
		if (i<size-1)
			tprintf(",");
	}
	tprintf("] /*");
	for (i=0;i<size;i++) {
		if (data[i] >= '!' && data[i] <= '~')
			tprintf("%c", data[i]);
		else
			tprintf(".");
	}
	tprintf(" */");
}

int is_within_offsets(offset,offsets,num_offsets)
size_t offset;
size_t* offsets;
int num_offsets;
{
	int i;
	int found = 0;
	for (i=0;i<num_offsets;i++) {
		if (offsets[i] == offset)
			found = 1;
	}
	return found;
}

void dump_flat_obj(flatobj)
flat_binder_object_t* flatobj;
{
	tprintf("{type=");
	switch (flatobj->type) {
	case kPackedLargeBinderHandleType:
		tprintf("kPackedLargeBinderHandleType,handle=0x%ld",flatobj->handle);
		break;
	case kPackedLargeBinderType:
		tprintf("kPackedLargeBinderType,binder=0x%08x,cookie=0x%08x",(u32)flatobj->binder,(u32)flatobj->cookie);
		break;
	case kPackedLargeBinderWeakHandleType:
		tprintf("kPackedLargeBinderWeakHandleType,handle=0x%ld",flatobj->handle);
		break;
	case kPackedLargeBinderWeakType:
		tprintf("kPackedLargeBinderWeakType,binder=0x%08x,cookie=0x%08x",(u32)flatobj->binder,(u32)flatobj->cookie);
		break;
	default:
		tprintf("%lu,length=%lu",flatobj->type,flatobj->length);
		break;
	}
	tprintf("}");
}

void comma()
{
	tprintf(",");
}

void dump_bytes_with_offsets(transdata,transdatasize,offsetsdata,offsetsdatasize,startfrom)
char* transdata;
int transdatasize;
size_t* offsetsdata;
int offsetsdatasize;
int startfrom;
{
	bool needsComma = false;
	tprintf("[");
	int numoffsets = offsetsdatasize/sizeof(size_t);
	char* currentpointer = transdata + startfrom;
	char* endpointer = currentpointer + transdatasize;
	char* currentdumpstart = currentpointer;
	while (currentpointer < endpointer) {
		int thisoffset = currentpointer - transdata;
		if (is_within_offsets(thisoffset,offsetsdata,numoffsets)) {
			if (currentdumpstart != currentpointer) {
				if (needsComma) comma();
				tprintf("rawbytes=");
				dump_bytes(currentdumpstart,currentpointer-currentdumpstart);
				needsComma = true;
			}
			if (needsComma) comma();
			tprintf("objref=");
			dump_flat_obj((flat_binder_object_t*) currentpointer);
			needsComma = true;
			currentpointer += sizeof(flat_binder_object_t);
			currentdumpstart = currentpointer;
		} else {
			currentpointer++;
		}
	}
	if (currentdumpstart != currentpointer) {
		if (needsComma) comma();
		tprintf("rawbytes=");
		dump_bytes(currentdumpstart,currentpointer-currentdumpstart);
		needsComma = true;
	}
	tprintf("]");
}

typedef struct
{
	u32 pid;
	u32 uid;
} presumed_transaction_contents;

void print_decimal_if_appropriate(number)
u32 number;
{
	if (number == 0xffffffff)
		tprintf("0x%08x",number);
	else
		tprintf("%u",number);
}

void dump_transaction_contents(transdata,transdatasize,offsetsdata,offsetsdatasize)
char* transdata;
int transdatasize;
size_t* offsetsdata;
int offsetsdatasize;
{
	tprintf("{");
	if (transdatasize < sizeof(presumed_transaction_contents))
		tprintf("...");
	else 
	{
		presumed_transaction_contents* contents = (presumed_transaction_contents*)transdata;
		tprintf("pid=");
		print_decimal_if_appropriate(contents->pid);
		tprintf(",uid=");
		print_decimal_if_appropriate(contents->uid);
		tprintf(",");
		dump_bytes_with_offsets(transdata,transdatasize,offsetsdata,offsetsdatasize,sizeof(presumed_transaction_contents));
	}
	tprintf("}");
}

void dump_transaction_data(tcp,transaction,is_transaction)
struct tcb *tcp;
binder_transaction_data_t* transaction;
bool is_transaction;
{
	if (is_transaction == true)
		tprintf("target=0x%08x,cookie=0x%08x,code=0x%08x,",(u32)transaction->target.handle,(u32)transaction->cookie,transaction->code);

	tprintf("flags=0x%08x,priority=%d,data_size=%d,offsets_size=%d,data=",transaction->flags,transaction->priority,transaction->data_size,transaction->offsets_size);
	if (transaction->flags & tfInline) {
		dump_bytes(transaction->data.buf,8);
	} else {
		char* transdata;
		size_t* offsetsdata;
		tprintf("{buffer=0x%08x,offsets=0x%08x,*buffer=",(u32)transaction->data.ptr.buffer,(u32)transaction->data.ptr.offsets);
		transdata=malloc(transaction->data_size);
		if (transdata != NULL) {
			offsetsdata=malloc(transaction->offsets_size);
			if (offsetsdata != NULL) {
				//if (umoven(tcp,(u32)transaction->data.ptr.buffer,1,transdata) == 0) {
				if (umoven(tcp,(u32)transaction->data.ptr.buffer,transaction->data_size,transdata) == 0 && umoven(tcp,(u32)transaction->data.ptr.offsets,transaction->offsets_size,(char*)offsetsdata)==0) {
					dump_transaction_contents(transdata,transaction->data_size,offsetsdata,transaction->offsets_size);
					//dump_bytes(transdata,transaction->data_size);
					//tprintf(",*offsets=");
					//dump_bytes(offsetsdata,transaction->offsets_size);
				} else
					tprintf("[...]");
				free(offsetsdata);
			}
			free(transdata);
		}
		tprintf("}");
	}
}

void
dump_write_data(tcp, buffer, size)
struct tcb *tcp;
signed long buffer;
unsigned long size;
{
	char* data = malloc(size);
	if (data != NULL) {
		if (umoven(tcp,buffer,size,data) == 0) {
			char* location = data;
			tprintf("[");
			while (location < data+size) {
				tprintf("{type=");
				u32 cmd;
				cmd = *((u32*)location);
				location+=sizeof(u32);
				switch (cmd) {
					case bcINCREFS:
						{
						u32 object;
						object = *((u32*)location);
						location+=sizeof(u32);
						tprintf("bcINCREFS,body={target=0x%08x}",object);
						break;
						}
					case bcINCREFS_DONE:
						{
						void* ptr;
						void* cookie;
						ptr = *((void**)location);
						location+=sizeof(void*);
						cookie = *((void**)location);
						location+=sizeof(void*);
						tprintf("bcINCREFS_DONE,body={ptr=0x%08x,cookie=0x%08x}",(u32)ptr,(u32)cookie);
						break;
						}
					case bcACQUIRE:
						{
						u32 object;
						object = *((u32*)location);
						location+=sizeof(u32);
						tprintf("bcACQUIRE,body={target=0x%08x}",object);
						break;
						}
					case bcACQUIRE_DONE:
						{
						void* ptr;
						void* cookie;
						ptr = *((void**)location);
						location+=sizeof(void*);
						cookie = *((void**)location);
						location+=sizeof(void*);
						tprintf("bcACQUIRE_DONE,body={ptr=0x%08x,cookie=0x%08x}",(u32)ptr,(u32)cookie);
						break;
						}
					case bcATTEMPT_ACQUIRE:
						{
						u32 priority;
						u32 target;
						priority = *((u32*)location);
						location+=sizeof(u32);
						target = *((u32*)location);
						location+=sizeof(u32);
						tprintf("bcATTEMPT_ACQUIRE,body={priority=0x%08x,target=0x%08x}",priority,target);
						break;
						}
					case bcACQUIRE_RESULT:
						{
						u32 result;
						result = *((u32*)location);
						location+=sizeof(u32);
						tprintf("bcACQUIRE_RESULT,body={result=0x%08x}",result);
						break;
						}
					case bcRELEASE:
						{
						u32 object;
						object = *((u32*)location);
						location+=sizeof(u32);
						tprintf("bcRELEASE,body={target=0x%08x}",object);
						break;
						}
					case bcDECREFS:
						{
						u32 object;
						object = *((u32*)location);
						location+=sizeof(u32);
						tprintf("bcDECREFS,body={target=0x%08x}",object);
						break;
						}
					case bcFREE_BUFFER:
						{
						void* ptr;
						ptr = *((void**)location);
						location+=sizeof(void*);
						tprintf("bcFREE_BUFFER,body={ptr=0x%08x}",(u32)ptr);
						break;
						}
					case bcRETRIEVE_ROOT_OBJECT:
						{
						u32 object;
						object = *((u32*)location);
						location+=sizeof(u32);
						tprintf("bcRETRIEVE_ROOT_OBJECT,body={pid=%d}",object);
						break;
						}
					case bcTRANSACTION:
					case bcREPLY:
						{
						binder_transaction_data_t* transaction;
						transaction = ((binder_transaction_data_t*)location);
						location += sizeof(binder_transaction_data_t);
						if (cmd == bcTRANSACTION)
							tprintf("bcTRANSACTION,body={");
						else
							tprintf("bcREPLY,body={");
						dump_transaction_data(tcp,transaction,cmd==bcTRANSACTION?true:false);
						tprintf("}");
						break;
						}
					case bcREGISTER_LOOPER:
						{
						tprintf("bcREGISTER_LOOPER");
						break;
						}
					case bcENTER_LOOPER:
						{
						tprintf("bcENTER_LOOPER");
						break;
						}
					case bcEXIT_LOOPER:
						{
						tprintf("bcEXIT_LOOPER");
						break;
						}
					/*case bcCATCH_ROOT_OBJECTS:
						{
						tprintf("bcCATCH_ROOT_OBJECTS");
						break;
						}*/
					case bcSTOP_PROCESS:
						{
						u32 target;
						u32 now;
						target = *((u32*)location);
						location+=sizeof(u32);
						now = *((u32*)location);
						location+=sizeof(u32);
						tprintf("bcSTOP_PROCESS,body={target=0x%08x,now=0x%08x}",target,now);
						break;
						}
					case bcSTOP_SELF:
						{
						u32 now;
						now = *((u32*)location);
						location+=sizeof(u32);
						tprintf("bcSTOP_SELF,body={now=0x%08x}",now);
						break;
						}
					case bcREQUEST_DEATH_NOTIFICATION:
						{
						u32 target;
						void* cookie;
						target = *((u32*)location);
						location+=sizeof(u32);
						cookie = *((void**)location);
						location+=sizeof(void*);
						tprintf("bcREQUEST_DEATH_NOTIFICATION,body={target=0x%08x,cookie=0x%08x}",target,(u32)cookie);
						break;
						}
					case bcCLEAR_DEATH_NOTIFICATION:
						{
						u32 target;
						void* cookie;
						target = *((u32*)location);
						location+=sizeof(u32);
						cookie = *((void**)location);
						location+=sizeof(void*);
						tprintf("bcCLEAR_DEATH_NOTIFICATION,body={target=0x%08x,cookie=0x%08x}",target,(u32)cookie);
						break;
						}
					case bcDEAD_BINDER_DONE:
						{
						void* cookie;
						cookie = *((void**)location);
						location+=sizeof(void*);
						tprintf("bcDEAD_BINDER_DONE,body={cookie=0x%08x}",(u32)cookie);
						break;
						}
					default:
						{
						tprintf("unknown");
						break;
						}
				}
				tprintf("}");
				if (location < data+size)
					tprintf(",");
			}
			
			tprintf("]");
		} else
			tprintf("{...}");
		
		free(data);
	} else
		tprintf("{...}");
}

void
dump_read_data(tcp, buffer, size)
struct tcb *tcp;
signed long buffer;
unsigned long size;
{
	char* data = malloc(size);
	if (data != NULL) {
		if (umoven(tcp,buffer,size,data) == 0) {
			char* location = data;
			tprintf("[");
			while (location < data+size) {
				tprintf("{type=");
				u32 cmd;
				cmd = *((u32*)location);
				location+=sizeof(u32);
				switch (cmd) {
					case brERROR:
						{
						u32 error;
						error = *((u32*)location);
						location++;
						tprintf("brERROR,body={error=%d}",error);
						break;
						}
					case brOK:
						tprintf("brOK");
						break;
					case brTIMEOUT:
						tprintf("brTIMEOUT");
						break;
					case brWAKEUP:
						tprintf("brWAKEUP");
						break;
					case brTRANSACTION:
					case brREPLY:
						{
						binder_transaction_data_t* transaction;
						transaction = ((binder_transaction_data_t*)location);
						location += sizeof(binder_transaction_data_t);
						if (cmd == brTRANSACTION)
							tprintf("brTRANSACTION,body={");
						else
							tprintf("brREPLY,body={");
						dump_transaction_data(tcp,transaction,cmd==brTRANSACTION?true:false);
						tprintf("}");
						break;
						}
					case brACQUIRE_RESULT:
						{
						u32 result;
						result = *((u32*)location);
						location++;
						tprintf("brACQUIRE_RESULT,body={result=%d}",result);
						break;
						}
					case brDEAD_REPLY:
						tprintf("brDEAD_REPLY");
						break;
					case brTRANSACTION_COMPLETE:
						tprintf("brTRANSACTION_COMPLETE");
						break;
					case brINCREFS:
					case brACQUIRE:
					case brRELEASE:
					case brDECREFS:
						{
						void* ptr;
						void* cookie;
						char* typestring = (cmd == brINCREFS) ? "brINCREFS" : (cmd == brACQUIRE) ? "brACQUIRE" : (cmd == brRELEASE) ? "brRELEASE" : "brDECREFS";
						ptr = *((void**)location);
						location++;
						cookie = *((void**)location);
						location++;
						tprintf("%s,body={ptr=0x%08x,cookie=0x%08x}",typestring,(u32)ptr,(u32)cookie);
						break;
						}
					case brATTEMPT_ACQUIRE:
						{
						u32 priority;
						void* ptr;
						void* cookie;
						priority = *((u32*)location);
						location++;
						ptr = *((void**)location);
						location++;
						cookie = *((void**)location);
						location++;
						tprintf("brATTEMPT_ACQUIRE,body={priority=%d,ptr=0x%08x,cookie=0x%08x}",priority,(u32)ptr,(u32)cookie);
						break;
						}
					case brEVENT_OCCURRED:
						tprintf("brEVENT_OCCURRED");
						break;
					case brNOOP:
						tprintf("brNOOP");
						break;
					case brSPAWN_LOOPER:
						tprintf("brSPAWN_LOOPER");
						break;
					case brFINISHED:
						tprintf("brFINISHED");
						break;
					case brDEAD_BINDER:
					case brCLEAR_DEATH_NOTIFICATION_DONE:
						{
						char* typestring = (cmd == brDEAD_BINDER) ? "brDEAD_BINDER" : "brCLEAR_DEATH_NOTIFICATION_DONE";
						void* cookie;
						cookie = *((void**)location);
						location++;
						tprintf("%s,body={cookie=0x%08x}",typestring,(u32)cookie);
						break;
						}
					case brFAILED_REPLY:
						tprintf("brFAILED_REPLY");
						break;
					default:
						tprintf("unknown");
				}
				tprintf("}");
				if (location < data+size)
					tprintf(",");
			}
			
			tprintf("]");
		} else
			tprintf("{...}");
		
		free(data);
	}
}
						
int
openbinder_ioctl(tcp, code, arg)
struct tcb *tcp;
long code;
long arg;
{
	switch (code) {
	case BINDER_WRITE_READ:
		if (exiting(tcp)) {
			binder_write_read_t wk;
			if (syserror(tcp) || umove(tcp,arg,&wk) < 0)
				tprintf(", %#lx", arg);
			else {
				tprintf(", {write_size=%ld,write_consumed=%ld,write_buffer=0x%lx,read_size=%ld,read_consumed=%ld,read_buffer=0x%lx",wk.write_size,wk.write_consumed,wk.write_buffer,wk.read_size,wk.read_consumed,wk.read_buffer);
				tprintf(",write_data=");
				dump_write_data(tcp,wk.write_buffer,wk.write_size);
				tprintf(",read_data=");
				dump_read_data(tcp,wk.read_buffer,wk.read_consumed);
				tprintf("}");
			}
		}
		break;
	case BINDER_SET_WAKEUP_TIME:
		if (exiting(tcp)) {
			binder_wakeup_time_t wk;
			if (syserror(tcp) || umove(tcp,arg,&wk) < 0)
				tprintf(", %#lx", arg);
			else {
				tprintf(", {time=...,priority=%d}",wk.priority);
			}
		}
		break;
	case BINDER_SET_IDLE_TIMEOUT:
	case BINDER_SET_REPLY_TIMEOUT:
		tprintf(", ...");
		break;
	case BINDER_SET_MAX_THREADS:
		if (exiting(tcp)) {
			size_t wk;
			if (syserror(tcp) || umove(tcp,arg,&wk) < 0)
				tprintf(", %#lx", arg);
			else {
				tprintf(", %d",(int)wk);
			}
		}
		break;
	case BINDER_SET_IDLE_PRIORITY:
	case BINDER_SET_CONTEXT_MGR:
	case BINDER_THREAD_EXIT:
		if (exiting(tcp)) {
			int wk;
			if (syserror(tcp) || umove(tcp,arg,&wk) < 0)
				tprintf(", %#lx", arg);
			else {
				tprintf(", %d",wk);
			}
		}
		break;
	case BINDER_VERSION:
		if (exiting(tcp)) {
			binder_version_t wk;
			if (syserror(tcp) || umove(tcp,arg,&wk) < 0)
				tprintf(", %#lx", arg);
			else {
				tprintf(", {protocol_version=%ld}",wk.protocol_version);
			}
		}
		break;
	default:
		break;
	}
	return 1;
}
