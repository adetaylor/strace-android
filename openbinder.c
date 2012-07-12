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
 */

#include "defs.h"
#ifdef HAVE_LINUX_BINDER_H
#include <inttypes.h>
#include <linux/types.h>

#include <linux/version.h>
#include <linux/ioctl.h>
#include <linux/binder.h>

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
struct flat_binder_object* flatobj;
{
	tprintf("{type=");
	switch (flatobj->type) {
	case BINDER_TYPE_BINDER:
		tprintf("BINDER_TYPE_BINDER,binder=0x%08x,cookie=0x%08x",(u32)flatobj->binder,(u32)flatobj->cookie);
		break;
	case BINDER_TYPE_WEAK_BINDER:
		tprintf("BINDER_TYPE_WEAK_BINDER,binder=0x%08x,cookie=0x%08x",(u32)flatobj->binder,(u32)flatobj->cookie);
		break;
	case BINDER_TYPE_HANDLE:
		tprintf("BINDER_TYPE_HANDLE,handle=0x%ld",flatobj->handle);
		break;
	case BINDER_TYPE_WEAK_HANDLE:
		tprintf("BINDER_TYPE_WEAK_HANDLE,handle=0x%ld",flatobj->handle);
		break;
	case BINDER_TYPE_FD:
		tprintf("BINDER_TYPE_FD,fd=%ld",flatobj->handle);
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
			dump_flat_obj((struct flat_binder_object*) currentpointer);
			needsComma = true;
			currentpointer += sizeof(struct flat_binder_object);
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
struct binder_transaction_data* transaction;
bool is_transaction;
{
	if (is_transaction == true)
		tprintf("target=0x%08x,cookie=0x%08x,code=0x%08x,",(u32)transaction->target.handle,(u32)transaction->cookie,transaction->code);

	tprintf("flags=0x%08x,data_size=%d,offsets_size=%d,data=",transaction->flags,transaction->data_size,transaction->offsets_size);
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
					case BC_INCREFS:
						{
						u32 object;
						object = *((u32*)location);
						location+=sizeof(u32);
						tprintf("BC_INCREFS,body={target=0x%08x}",object);
						break;
						}
					case BC_INCREFS_DONE:
						{
						void* ptr;
						void* cookie;
						ptr = *((void**)location);
						location+=sizeof(void*);
						cookie = *((void**)location);
						location+=sizeof(void*);
						tprintf("BC_INCREFS_DONE,body={ptr=0x%08x,cookie=0x%08x}",(u32)ptr,(u32)cookie);
						break;
						}
					case BC_ACQUIRE:
						{
						u32 object;
						object = *((u32*)location);
						location+=sizeof(u32);
						tprintf("BC_ACQUIRE,body={target=0x%08x}",object);
						break;
						}
					case BC_ACQUIRE_DONE:
						{
						void* ptr;
						void* cookie;
						ptr = *((void**)location);
						location+=sizeof(void*);
						cookie = *((void**)location);
						location+=sizeof(void*);
						tprintf("BC_ACQUIRE_DONE,body={ptr=0x%08x,cookie=0x%08x}",(u32)ptr,(u32)cookie);
						break;
						}
					case BC_ATTEMPT_ACQUIRE:
						{
						u32 priority;
						u32 target;
						priority = *((u32*)location);
						location+=sizeof(u32);
						target = *((u32*)location);
						location+=sizeof(u32);
						tprintf("BC_ATTEMPT_ACQUIRE,body={priority=0x%08x,target=0x%08x}",priority,target);
						break;
						}
					case BC_ACQUIRE_RESULT:
						{
						u32 result;
						result = *((u32*)location);
						location+=sizeof(u32);
						tprintf("BC_ACQUIRE_RESULT,body={result=0x%08x}",result);
						break;
						}
					case BC_RELEASE:
						{
						u32 object;
						object = *((u32*)location);
						location+=sizeof(u32);
						tprintf("BC_RELEASE,body={target=0x%08x}",object);
						break;
						}
					case BC_DECREFS:
						{
						u32 object;
						object = *((u32*)location);
						location+=sizeof(u32);
						tprintf("BC_DECREFS,body={target=0x%08x}",object);
						break;
						}
					case BC_FREE_BUFFER:
						{
						void* ptr;
						ptr = *((void**)location);
						location+=sizeof(void*);
						tprintf("BC_FREE_BUFFER,body={ptr=0x%08x}",(u32)ptr);
						break;
						}
					case BC_TRANSACTION:
					case BC_REPLY:
						{
						struct binder_transaction_data* transaction;
						transaction = ((struct binder_transaction_data*)location);
						location += sizeof(struct binder_transaction_data);
						if (cmd == BC_TRANSACTION)
							tprintf("BC_TRANSACTION,body={");
						else
							tprintf("BC_REPLY,body={");
						dump_transaction_data(tcp,transaction,cmd==BC_TRANSACTION?true:false);
						tprintf("}");
						break;
						}
					case BC_REGISTER_LOOPER:
						{
						tprintf("BC_REGISTER_LOOPER");
						break;
						}
					case BC_ENTER_LOOPER:
						{
						tprintf("BC_ENTER_LOOPER");
						break;
						}
					case BC_EXIT_LOOPER:
						{
						tprintf("BC_EXIT_LOOPER");
						break;
						}
					case BC_REQUEST_DEATH_NOTIFICATION:
						{
						u32 target;
						void* cookie;
						target = *((u32*)location);
						location+=sizeof(u32);
						cookie = *((void**)location);
						location+=sizeof(void*);
						tprintf("BC_REQUEST_DEATH_NOTIFICATION,body={target=0x%08x,cookie=0x%08x}",target,(u32)cookie);
						break;
						}
					case BC_CLEAR_DEATH_NOTIFICATION:
						{
						u32 target;
						void* cookie;
						target = *((u32*)location);
						location+=sizeof(u32);
						cookie = *((void**)location);
						location+=sizeof(void*);
						tprintf("BC_CLEAR_DEATH_NOTIFICATION,body={target=0x%08x,cookie=0x%08x}",target,(u32)cookie);
						break;
						}
					case BC_DEAD_BINDER_DONE:
						{
						void* cookie;
						cookie = *((void**)location);
						location+=sizeof(void*);
						tprintf("BC_DEAD_BINDER_DONE,body={cookie=0x%08x}",(u32)cookie);
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
					case BR_ERROR:
						{
						u32 error;
						error = *((u32*)location);
						location++;
						tprintf("BR_ERROR,body={error=%d}",error);
						break;
						}
					case BR_OK:
						tprintf("BR_OK");
						break;
					case BR_TRANSACTION:
					case BR_REPLY:
						{
						struct binder_transaction_data* transaction;
						transaction = ((struct binder_transaction_data*)location);
						location += sizeof(struct binder_transaction_data);
						if (cmd == BR_TRANSACTION)
							tprintf("BR_TRANSACTION,body={");
						else
							tprintf("BR_REPLY,body={");
						dump_transaction_data(tcp,transaction,cmd==BR_TRANSACTION?true:false);
						tprintf("}");
						break;
						}
					case BR_ACQUIRE_RESULT:
						{
						u32 result;
						result = *((u32*)location);
						location++;
						tprintf("BR_ACQUIRE_RESULT,body={result=%d}",result);
						break;
						}
					case BR_DEAD_REPLY:
						tprintf("BR_DEAD_REPLY");
						break;
					case BR_TRANSACTION_COMPLETE:
						tprintf("BR_TRANSACTION_COMPLETE");
						break;
					case BR_INCREFS:
					case BR_ACQUIRE:
					case BR_RELEASE:
					case BR_DECREFS:
						{
						void* ptr;
						void* cookie;
						const char* typestring = (cmd == BR_INCREFS) ? "BR_INCREFS" : (cmd == BR_ACQUIRE) ? "BR_ACQUIRE" : (cmd == BR_RELEASE) ? "BR_RELEASE" : "BR_DECREFS";
						ptr = *((void**)location);
						location++;
						cookie = *((void**)location);
						location++;
						tprintf("%s,body={ptr=0x%08x,cookie=0x%08x}",typestring,(u32)ptr,(u32)cookie);
						break;
						}
					case BR_ATTEMPT_ACQUIRE:
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
						tprintf("BR_ATTEMPT_ACQUIRE,body={priority=%d,ptr=0x%08x,cookie=0x%08x}",priority,(u32)ptr,(u32)cookie);
						break;
						}
					case BR_NOOP:
						tprintf("BR_NOOP");
						break;
					case BR_SPAWN_LOOPER:
						tprintf("BR_SPAWN_LOOPER");
						break;
					case BR_FINISHED:
						tprintf("BR_FINISHED");
						break;
					case BR_DEAD_BINDER:
					case BR_CLEAR_DEATH_NOTIFICATION_DONE:
						{
						const char* typestring = (cmd == BR_DEAD_BINDER) ? "BR_DEAD_BINDER" : "BR_CLEAR_DEATH_NOTIFICATION_DONE";
						void* cookie;
						cookie = *((void**)location);
						location++;
						tprintf("%s,body={cookie=0x%08x}",typestring,(u32)cookie);
						break;
						}
					case BR_FAILED_REPLY:
						tprintf("BR_FAILED_REPLY");
						break;
					default:
						tprintf("unknown");
						break;
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
			struct binder_write_read wk;
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
	case BINDER_SET_IDLE_TIMEOUT:
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
			struct binder_version wk;
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

#endif
