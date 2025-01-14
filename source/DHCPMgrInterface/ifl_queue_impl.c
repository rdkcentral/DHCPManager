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

#include "ifl_conf.h"
#include "ifl_priv.h"

typedef struct _ifl_queue_t {
    void* data;
    #ifdef IFL_DYNAMIC_QUEUE
    struct _ifl_queue_t* next;
    #endif
} ifl_queue_t;

typedef struct _ifl_qInstance_t {
    ifl_queue_t  q[IFL_MAX_QLEN];
    #ifndef IFL_DYNAMIC_QUEUE
    unsigned int  head;
    unsigned int  tail;
    unsigned int  full;
    #else
    ifl_queue_t*  tail;
    #endif
} ifl_qInstance_t;


/*
 * static globals
 */
static unsigned int     qInstIdx  = 0;

ifl_ret createQ (void** qHdl)
{
    ifl_ret ret = IFL_SUCCESS;

    if (qInstIdx < IFL_MAX_QUEUE)
    {
        *qHdl = malloc(sizeof(ifl_qInstance_t));
        ((ifl_qInstance_t*)*qHdl)->head = 0;
        ((ifl_qInstance_t*)*qHdl)->tail = 0;
        ((ifl_qInstance_t*)*qHdl)->full = 0;
        qInstIdx++;
        IFL_LOG_INFO("Created %p(%d)", *qHdl, qInstIdx);
    }
    else
    {
        IFL_LOG_ERROR("No more room for Q creation! - %d/%d", qInstIdx, IFL_MAX_QUEUE);
        ret = IFL_ERROR;
    }

    return ret;
}


ifl_ret pushToQ (void* qHdl, void* qdata)
{
    ifl_ret ret = IFL_ERROR;

    if (qHdl)
    {
        ifl_qInstance_t* qIns = (ifl_qInstance_t*)qHdl;

        if (!qIns->full)
        {
            qIns->q[qIns->tail].data = qdata;
            if ((qIns->tail + 1) % IFL_MAX_QLEN != qIns->head)
            {
                qIns->tail = (qIns->tail+1) % IFL_MAX_QLEN;
            }
            else
            {
                qIns->full = !qIns->full;
            }
            ret = IFL_SUCCESS;
        }
        else
        {
            IFL_LOG_ERROR("Q is Full!  %p - %d/%d", qHdl, qIns->head, qIns->tail);
        }
    }

    return ret;
}


ifl_ret popFromQ (void* qHdl, void** qdata)
{
    ifl_ret ret = IFL_ERROR;

    if (qHdl)
    {
        ifl_qInstance_t* qIns = qHdl;

        if (qIns->head != qIns->tail)
        {
            *qdata = qIns->q[qIns->head].data;
            qIns->head = (qIns->head+1) % IFL_MAX_QLEN;
            if (qIns->full)
            {
                qIns->tail = (qIns->tail+1) % IFL_MAX_QLEN;
                qIns->full = !qIns->full;
            }
            ret = IFL_SUCCESS;
         }
         else
         {
            IFL_LOG_ERROR("Q is Empty! %p - %d|%d", qHdl, qIns->head, qIns->tail);
         }
    }

    return ret;
}


ifl_ret destroyQ (void** qHdl)
{
    ifl_ret ret = IFL_ERROR;

    if (qInstIdx)
    {
        if (qHdl && *qHdl)
        {
            free (*qHdl);
            *qHdl = NULL;
            qInstIdx--;
            IFL_LOG_INFO("Destroyed %p(%d)", *qHdl, qInstIdx+1);

            ret = IFL_SUCCESS;
        }
    }
    else
    {
        IFL_LOG_ERROR("No more Qs to destroy! %p/%d", *qHdl, qInstIdx);
    }

    return ret;
}
