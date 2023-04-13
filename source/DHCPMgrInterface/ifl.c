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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sysinfo.h>
#include "errno.h"
#include "sysevent/sysevent.h"
#include "safec_lib_common.h"
#include "ifl_priv.h"
#include "ifl_queue_impl.h"
#include "ifl_thread.h"

#define LOCALHOST   "127.0.0.1"

typedef struct _thread_data_t {
    void*        qObj;
    uint8        ctxID;
} thread_data_t;

typedef struct _q_data_t {
    fptr_t       cb;
    char         eValue[BUFLEN_64];
} q_data_t;

typedef struct _handler_t {
    fptr_t       cb;
    uint8        ctxID;
    ifl_event_type   eType;
} handler_t;

typedef struct _event_handler_map_t {
    char         event[BUFLEN_64];
    handler_t    handler[IFL_MAX_CONTEXT];
    uint8        handlerCount;
    async_id_t   asyncID;
} event_handler_map_t;

typedef struct _q_context_idx_map_t {
    char         qCtx[BUFLEN_16];
    void*        qObj;
} q_context_idx_map_t;

/*
 * static globals
 */
static event_handler_map_t  evtToHdlMap[IFL_MAX_EVENT_HANDLER_MAP];
static q_context_idx_map_t  ctxToIdxMap[IFL_MAX_CONTEXT];
static uint8                thdToIdxMap[IFL_MAX_CONTEXT];
static int       sysevent_fd;
static token_t   sysevent_token;

/*
 * Static prototypes
 */
static void* _task_manager_thrd (void *value);
static void* _task_thrd (void *value);
static uint8 _get_ctx_id (char* ctx);
static uint8 _get_evt_id (char* event, uint8 addEvent);

/*
 * Static API definitions
 */
static uint8 _get_ctx_id (char* ctx)
{
    static uint8 nextCtxIdx = 0;
    uint8 idx = 0;

    for ( ;idx < nextCtxIdx; idx++)
    {
        if (!strncmp(ctxToIdxMap[idx].qCtx, ctx, BUFLEN_16))
        {
            break;
        }
    }
    if (idx == nextCtxIdx || !nextCtxIdx)
    {
        if (nextCtxIdx < IFL_MAX_CONTEXT)
        {
            if (createQ(&ctxToIdxMap[idx=nextCtxIdx].qObj) == IFL_SUCCESS)
            {
                errno_t ret = 0;
                IFL_LOG_INFO("[%d] New Q %p", idx, ctxToIdxMap[idx].qObj);
                ret = strcpy_s(ctxToIdxMap[idx].qCtx, BUFLEN_16, ctx);
                ERR_CHK(ret);
                nextCtxIdx++;
            }
        }
        else
        {
            idx = IFL_MAX_CONTEXT;
        }
    }
    return idx;
}


static uint8 _get_evt_id (char* event, uint8 addEvent)
{
    static uint8 nextEvtHdlIdx = 0;
    uint8  idx = nextEvtHdlIdx;

    if (idx < IFL_MAX_EVENT_HANDLER_MAP)
    {
        for (idx=0; idx < nextEvtHdlIdx; idx++)
        {
            if (!strncmp(evtToHdlMap[idx].event, event, BUFLEN_64))
            {
                break;
            }
        }

        if (addEvent && (idx == nextEvtHdlIdx))
        {
            errno_t ret = strcpy_s(evtToHdlMap[idx].event, BUFLEN_64, event);
            ERR_CHK(ret);
            evtToHdlMap[idx].handlerCount = 0;
            nextEvtHdlIdx++;
        }
    }

    return idx;
}


/*
 * External API definitions
 */
ifl_ret ifl_init (char* mainCtx)
{
    ifl_ret ret = IFL_SUCCESS;

    memset(evtToHdlMap, 0, sizeof(evtToHdlMap));
    memset(ctxToIdxMap, 0, sizeof(ctxToIdxMap));
    memset(thdToIdxMap, 0, sizeof(thdToIdxMap));

    ifl_thread_init();

    sysevent_fd = sysevent_open(LOCALHOST, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, mainCtx, &sysevent_token);

    if (IFL_SUCCESS != (ret = ifl_thread_create(0, _task_manager_thrd, NULL)))
    {
        IFL_LOG_ERROR("Failed creating sysevent handler! ret: %d", ret);
    }

    return ret;
}


ifl_ret ifl_register_event_handler (char* event, ifl_event_type eType, char* callerCtx, fptr_t cb)
{
    ifl_ret ret = IFL_ERROR;
    uint8 evtID = 0;
    uint8 ctxID = 0;

    if (!event || !callerCtx || !cb)
    {
        IFL_LOG_ERROR("Invalid register args!");
        return ret;
    }

    if ((ctxID = _get_ctx_id(callerCtx)) == IFL_MAX_CONTEXT)
    {
        IFL_LOG_ERROR("Maximum caller context(%d) registered!", IFL_MAX_CONTEXT);
        return ret;
    }

    if ((evtID = _get_evt_id(event, 1)) == IFL_MAX_EVENT_HANDLER_MAP)
    {
        IFL_LOG_ERROR("Maximum events(%d) registered!", evtID);
        return ret;
    }

    if (evtToHdlMap[evtID].handlerCount < IFL_MAX_CONTEXT)
    {
        evtToHdlMap[evtID].handler[evtToHdlMap[evtID].handlerCount].ctxID  = ctxID;
        evtToHdlMap[evtID].handler[evtToHdlMap[evtID].handlerCount].eType  = eType;
        evtToHdlMap[evtID].handler[evtToHdlMap[evtID].handlerCount].cb     = cb;

        if (eType == IFL_EVENT_NOTIFY)
        {
            sysevent_set_options(sysevent_fd, sysevent_token, evtToHdlMap[evtID].event, TUPLE_FLAG_EVENT);
        }
        sysevent_setnotification(sysevent_fd, sysevent_token, evtToHdlMap[evtID].event, &evtToHdlMap[evtID].asyncID);

        IFL_LOG_INFO("Registered event: %s, ctxID: %d, eType: %d, hdlrCount: %d, evtID: %d, cb: %p"
                                , evtToHdlMap[evtID].event
                                , evtToHdlMap[evtID].handler[evtToHdlMap[evtID].handlerCount].ctxID
                                , evtToHdlMap[evtID].handler[evtToHdlMap[evtID].handlerCount].eType
                                , evtToHdlMap[evtID].handlerCount, evtID
                                , evtToHdlMap[evtID].handler[evtToHdlMap[evtID].handlerCount].cb);

        evtToHdlMap[evtID].handlerCount++;
        ret = IFL_SUCCESS;
    }
    else
    {
        IFL_LOG_ERROR("Event(%s) reached max subcription!", evtToHdlMap[evtID].event);
    }

    return ret;
}


/*ifl_ret ifl_unregister_event_handler (char* event, char* callerCtx)
{
    ifl_ret ret = IFL_SUCCESS;

    return ret;
}


ifl_ret ifl_get_event (char* event, char* value, int valueLength)
{
    ifl_ret ret = IFL_SUCCESS;

    return ret;
}


ifl_ret ifl_set_event (char* event, char* value)
{
    ifl_ret ret = IFL_SUCCESS;

    return ret;
}*/


ifl_ret ifl_deinit(void)
{
    ifl_ret ret = IFL_SUCCESS;

    /*
     * Define API
     */

    return ret;
}

static void *_task_manager_thrd(void * value)
{
    UNREFERENCED_PARAMETER(value);
    IFL_LOG_INFO("Created");

    for (;;)
    {
        if (access("/tmp/dhcpmgr_initialized", F_OK) == 0) {
        char event[BUFLEN_64]    = {0};
        char eValue[BUFLEN_64]   = {0};
        int  eventLen  = sizeof(event);
        int  eValueLen = sizeof(eValue);
        int  err = 0;
        async_id_t getnotification_id;

        err = sysevent_getnotification(sysevent_fd, sysevent_token, event, &eventLen,
                                      eValue, &eValueLen, &getnotification_id);

        IFL_LOG_INFO("Event getting triggered is [%s]", event);

        if (err)
        {
            IFL_LOG_ERROR("Sysevent get notification failed! err: %d", err);
        }
        else
        {
            uint8 evtID = 0;
            uint8 ctxID = 0;
            uint8 idx   = 0;

            /* _get_evt_id is not thread safe */
            if ((evtID = _get_evt_id(event, 0)) == IFL_MAX_EVENT_HANDLER_MAP)
            {
                IFL_LOG_ERROR("Event(%s) not found in registered list! Ambiguous!", event);
                continue;
            }

            for (idx = 0; idx < evtToHdlMap[evtID].handlerCount; idx++)
            {
                ifl_ret ret  = IFL_ERROR;
                ifl_ret retL = IFL_ERROR;
                uint8 skipLock = 0;

                q_data_t* qData = (q_data_t*)malloc(sizeof(q_data_t));
                qData->cb = evtToHdlMap[evtID].handler[idx].cb;
                int rc = strcpy_s(qData->eValue, BUFLEN_64, eValue);
                ERR_CHK(rc);
                ctxID = evtToHdlMap[evtID].handler[idx].ctxID;

                /* spin lock for thread flag - Try */
                if (IFL_SUCCESS == (retL=ifl_thread_lock(ctxID, IFL_LOCK_TYPE_SPIN_NO_WAIT)))
                {
                    if ((skipLock = thdToIdxMap[ctxID]))
                    {
                        ifl_thread_lock(ctxID, IFL_LOCK_TYPE_MUTEX_WAIT);
                    }
                ifl_thread_unlock(ctxID, IFL_LOCK_TYPE_SPIN);
                }
                else
                {
                    if (IFL_LOCK_BUSY == retL)
                    {
                        //IFL_LOG_INFO("[%d] Skip lock acquire.", ctxID);
                    }
                    else
                    {
                        //IFL_LOG_ERROR("[%d] Skip handling event %s", ctxID, event);
                        free(qData);
                        continue;
                    }
                }

                if (IFL_SUCCESS !=
                      (ret = pushToQ(ctxToIdxMap[ctxID].qObj, (void*)qData)))
                {
                    IFL_LOG_ERROR("[%d] Push event %s failed!", ctxID, event);
                }

                if (skipLock)
                {
                    ifl_thread_unlock(ctxID, IFL_LOCK_TYPE_MUTEX);
                }
                else
                {
                    if (IFL_SUCCESS == ret)
                    {
                        void* tData = malloc(sizeof(thread_data_t));
                        ((thread_data_t*)tData)->qObj     = ctxToIdxMap[ctxID].qObj;
                        ((thread_data_t*)tData)->ctxID    = ctxID;

                        thdToIdxMap[ctxID] = 1;

                        if (IFL_SUCCESS !=
                             (ret=ifl_thread_create(IFL_THRD_PROP_DETACH, _task_thrd, tData)))
                        {
                            IFL_LOG_ERROR("[%d] create task thread Failed! Event: %s ret: %d"
                                                                          , ctxID, event, ret);
                            thdToIdxMap[ctxID] = 0;
                        }
                    }
                }
            }
        }
    }
    else{
        sleep(2);
    }
    }
    IFL_LOG_INFO("Exit.");
    return NULL;
}

static void *_task_thrd(void *tData)
{
    ifl_ret retL     = IFL_ERROR;
    q_data_t* qData  = NULL;
    uint8 gotNewTask = 0;
    IFL_LOG_INFO("[%d] Created.", ((thread_data_t*)tData)->ctxID);

    do {
        while (ifl_thread_lock(((thread_data_t*)tData)->ctxID, IFL_LOCK_TYPE_MUTEX),
              popFromQ(((thread_data_t*)tData)->qObj, (void**)&qData) == IFL_SUCCESS)
        {
            ifl_thread_unlock(((thread_data_t*)tData)->ctxID, IFL_LOCK_TYPE_MUTEX);
            if (qData)
            {
                IFL_LOG_INFO("[%d] Pop %p", ((thread_data_t*)tData)->ctxID, (void*)qData->cb);
                if (qData->cb)
                {
                    /* Reduce the thrd priority? */
                    ifl_thread_lower_priority(((thread_data_t*)tData)->ctxID);

                    qData->cb(&qData->eValue);

                    /* Reset the thrd priority? */
                    ifl_thread_reset_priority(((thread_data_t*)tData)->ctxID);
                }
                free((void*)qData);
            }
        }
        ifl_thread_unlock(((thread_data_t*)tData)->ctxID, IFL_LOCK_TYPE_MUTEX);

        /* not advisable here */
        //ifl_thread_yield();

        if (IFL_SUCCESS ==
                (retL = ifl_thread_lock(((thread_data_t*)tData)->ctxID, IFL_LOCK_TYPE_SPIN_NO_WAIT)))
        {
            gotNewTask = 0;
            thdToIdxMap[((thread_data_t*)tData)->ctxID] = 0;
            ifl_thread_unlock(((thread_data_t*)tData)->ctxID, IFL_LOCK_TYPE_SPIN);
        }
        else
        {
            if (IFL_LOCK_BUSY == retL)
            {
                IFL_LOG_INFO("[%d] Reset.", ((thread_data_t*)tData)->ctxID);
                ifl_thread_yield(((thread_data_t*)tData)->ctxID);
                gotNewTask = 1;
            }
        }
    } while (gotNewTask);

    IFL_LOG_INFO("[%d] Exit.", ((thread_data_t*)tData)->ctxID);
    free(tData);
    return NULL;
}
