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

#ifndef __IFL_THREAD_H__
#define __IFL_THREAD_H__

typedef void*(*tfptr_t)(void*);
typedef void ifl_lock_t;

typedef enum _thread_prop {
    IFL_THRD_PROP_NONE              = 0x00,
    IFL_THRD_PROP_JOIN              = 0x01,
    IFL_THRD_PROP_DETACH            = 0x02,
    IFL_THRD_PROP_CANCEL            = 0x04,
    IFL_THRD_PROP_NO_CANCEL         = 0x08,
    IFL_THRD_PROP_CANCEL_ASYNC      = 0x10,
    IFL_THRD_PROP_CANCEL_DEFER      = 0x20,
    /*
     * fill here
     */
    IFL_THRD_PROP_MAX               = 0xFF
} thread_prop;

typedef enum _lock_type {
    IFL_LOCK_TYPE_MUTEX             = 0x00,
    IFL_LOCK_TYPE_MUTEX_WAIT        = 0x01,
    IFL_LOCK_TYPE_MUTEX_NO_WAIT     = 0x02,
    IFL_LOCK_TYPE_SPIN              = 0x04,
    IFL_LOCK_TYPE_SPIN_WAIT         = 0x08,
    IFL_LOCK_TYPE_SPIN_NO_WAIT      = 0x10,
    IFL_LOCK_TYPE_SEM               = 0x20,
    /*
     * fill here
     */
    IFL_LOCK_TYPE_MAX               = 0xFF
} lock_type;


/*
 * IFL thread API prototypes
 */
ifl_ret ifl_thread_init (void);
ifl_ret ifl_thread_create (thread_prop tPrpty, tfptr_t tFunc, void* tData);
ifl_ret ifl_thread_lock (uint8 tID, lock_type lType);
ifl_ret ifl_thread_unlock (uint8 tID, lock_type lType);
ifl_ret ifl_thread_yield (uint8 tID);
ifl_ret ifl_thread_lower_priority (uint8 tID);
ifl_ret ifl_thread_reset_priority (uint8 tID);
ifl_ret ifl_thread_deinit (void);
ifl_ret ifl_lock_init (ifl_lock_t** lock);
ifl_ret ifl_lock (ifl_lock_t* lock, lock_type lType);
ifl_ret ifl_unlock (ifl_lock_t* lock, lock_type lType);
ifl_ret ifl_lock_deinit (ifl_lock_t** lock);
ifl_ret ifl_gain_priority(void);
ifl_ret ifl_lose_priority(void);
#endif
