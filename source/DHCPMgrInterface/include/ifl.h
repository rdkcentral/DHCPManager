/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2020 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
************************************************************************************/

#ifndef __INTERFACE_LAYER_H__
#define __INTERFACE_LAYER_H__

typedef void(*fptr_t)(void*);
typedef unsigned char uint8;

/*
 * define interface layer return type codes.
 */

typedef enum _event_type {
    IFL_EVENT_NOTIFY_FALSE = 0,
    IFL_EVENT_NOTIFY_TRUE
} ifl_event_type;

typedef enum _context_type {
    IFL_CTX_STATIC = 0,
    IFL_CTX_DYNAMIC
} ifl_ctx_type;

/*
 * define interface layer return type codes.
 */
typedef enum _ifl_ret {
    IFL_SUCCESS                = 0x0000,
    IFL_ARG_INVALID            = 0x0001,
    IFL_MEMORY_ERROR           = 0x0002,
    IFL_Q_CREATE_ERROR         = 0x0004,
    IFL_Q_PUSH_ERROR           = 0x0008,
    IFL_Q_POP_ERROR            = 0x0010,
    IFL_THRD_CREATE_ERROR      = 0x0020,
    IFL_THRD_PROP_ERROR        = 0x0040,
    IFL_LOCK_INIT_ERROR        = 0x0080,
    IFL_LOCK_ERROR             = 0x0100,
    IFL_LOCK_BUSY              = 0x0200,
    IFL_UNLOCK_ERROR           = 0x0400,
    IFL_DEADLOCK               = 0x0800,
    IFL_SYSEVENT_ERROR         = 0x1000,
    IFL_ERROR                  = 0xFFFF
} ifl_ret;

/*
 * Interface layer external API prototypes.
 */
ifl_ret  ifl_init (char* mainCtx);
ifl_ret  ifl_init_ctx (char* ctx, ifl_ctx_type cType);
ifl_ret  ifl_register_event_handler (char* event, ifl_event_type eType, char* callerCtx, fptr_t cb);
ifl_ret  ifl_unregister_event_handler (char* event, char* callerCtx);

ifl_ret  ifl_get_event (char* event, char* value, int valueLength);
ifl_ret  ifl_set_event (char* event, char* value);

ifl_ret  ifl_deinit_ctx (char* ctx);
ifl_ret  ifl_deinit (void);

#endif
